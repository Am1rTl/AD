(ns backend.handler
  (:require [backend.auth :refer [create-token hash-passwd verify-passwd]]
            [backend.db.comments :as comments-db]
            [backend.db.db :refer [db-cfg]]
            [backend.db.quotes :as quotes-db]
            [backend.db.users :as users-db]
            [ring.util.response :refer [redirect response]]))

(defn create-user [user]
  (let
   [hashed-user (assoc user :passwd (hash-passwd (:passwd user)))]
    (users-db/create-user db-cfg hashed-user)))

(defn healthcheck [_]
  {:status 200
   :body "healthy"})

(defn get-users [_]
  (let [users (users-db/list-users db-cfg {:user-fields (users-db/user-fields)})]
    {:status 200
     :body users}))

(defn get-user-by-id [{{:keys [id]} :path-params}]
  (let [user (users-db/get-user-by-id db-cfg {:id (Integer/parseInt id)
                                              :user-fields (users-db/user-fields)})]
    {:status 228
     :body user}))

(defn get-comments-of-quote [{{:keys [id]} :path-params
                              identity :identity}]
  (let [id (Integer/parseInt id)
        quote (quotes-db/get-quote-by-id db-cfg {:id id
                                                 :quote-fields (quotes-db/quote-fields)})
        user_id (:user identity)
        comments (comments-db/get-comments-by-quote-id db-cfg {:quote_id id
                                                               :comment-fields (comments-db/only-comment-fields)})]
    (if (and (pos-int? user_id) (pos-int? (:user_id quote)))
      (if (or (= (:user identity) (:user_id quote)) (not (:is_private quote)))
        {:status 200
         :body {:comments comments}}
        {:status 401
         :body {:error "unauthorized"
                :message "can't view this maaan"}})
      {:status 406
       :body {:error "params wrong"
              :message "something wroong, I can fell that"}})))

(defn get-quote-by-id [{{:keys [id]} :path-params
                        identity :identity}]
  (let [id (Integer/parseInt id)
        quote (quotes-db/get-quote-by-id db-cfg {:id id
                                                 :quote-fields (quotes-db/quote-fields)})
        user_id (:user identity)
        comments (comments-db/get-comments-by-quote-id db-cfg {:quote_id id
                                                               :comment-fields (comments-db/only-comment-fields)})]
    (if (and (pos-int? user_id) (not (empty? quote)))
      (if (or (= (:user identity) (:user_id quote)) (not (:is_private quote)))
        {:status 200
         :body (conj quote {:comments comments})}

        {:status 401
         :body {:error "can't get quote"
                :message "not yours quote"}})
      {:status 404
       :body {:error "not found"
              :message "something wroong, I can fell that"}})))

(defn get-all-nonprivate-comments [{identity :identity}]
  (let [quotes (quotes-db/list-quotes db-cfg {:quote-fields (quotes-db/quote-fields)})
        public (filter (fn [q] (not= (:is_private q) true)) quotes)
        comments (mapcat (fn [q] (comments-db/get-comments-by-quote-id db-cfg {:quote_id (:quote_id q)
                                                                               :comment-fields (comments-db/only-comment-fields)})) public)]
    {:status 200
     :body {:comments comments}}))

(defn get-comment-by-id [{{:keys [id]} :path-params}]
  (let [id (Integer/parseInt id)
        comment (comments-db/get-comment-by-id db-cfg {:id id
                                                       :comment-fields (comments-db/comment-fields)})
        quote (quotes-db/get-quote-by-id db-cfg {:id (:quote_id comment)
                                                 :quote-fields (quotes-db/quote-fields)})]
    {:status 200
     :body {:comment (assoc comment :quote quote)}}))

(defn create-comment-for-quote [{{:keys [id]} :path-params
                                 {:keys [comment]} :body-params

                                 identity :identity}]
  (if (= (count comment) 0)
    {:status 406
     :body {:error "wrong params"
            :message "Empty string"
            :body {:comment comment}}}
    (try
      (let [comment-data {:comment (str (read-string comment))
                          :user_id (:user identity)
                          :quote_id (Integer/parseInt id)}
            comment (comments-db/create-comment db-cfg comment-data)]
        (response {:comment comment}))
      (catch java.sql.SQLException e {:status 418
                                      :body {:error "comment creation error"
                                             :message (.getMessage e)}})
      (catch Exception e {:status 500
                          :body {:error "internal wtf"
                                 :message (.getMessage e)}}))))

(defn get-quotes [{identity :identity}]
  (let [quotes (filter (fn [q] (or (not (:is_private q)) (= (:user_id q) (:user identity))))
                       (quotes-db/list-quotes db-cfg {:quote-fields (quotes-db/quote-fields)}))]
    {:status 200
     :body quotes}))

(defn get-my-quotes [{identity :identity}]
  (let [quotes (quotes-db/get-quote-by-user-id db-cfg {:id (:user identity)
                                                       :quote-fields (quotes-db/quote-fields)})]
    (if (map? quotes)
      {:status 200
       :body (assoc [] quotes)}
      {:status 200
       :body quotes})))

(defn create-quote [{{:keys [title author text is_private]} :body-params
                     body :body-params
                     identity :identity}]
  (if (or
       (empty? identity)
       (= (count title) 0)
       (= (count text) 0))
    {:status 417
     :body {:error "wrong params"
            :message "Empty string"
            :body body}}
    (try
      (let [quote (quotes-db/create-quote db-cfg
                                          {:title title
                                           :author author
                                           :text text
                                           :is_private is_private
                                           :user_id (:user identity)})]
        (response {:quote quote}))
      (catch java.sql.SQLException e {:status 418
                                      :body {:error "quote creation error"
                                             :message (.getMessage e)}})
      (catch Exception e {:status 500
                          :body {:error "internal wtf"
                                 :message (.getMessage e)}}))))

(defn post-login [{{:keys [username password]} :body-params}]
  (let [user (users-db/get-user-by-name db-cfg {:name username})]
    (if (nil? user)
      {:status 404
       :body
       {:error "login failed"
        :message "Wrong user"}}
      (if (verify-passwd password (:passwd user))
        (let [token (create-token {:user (:user_id user)})]
          {:status 200
           :body {:token token
                  :user_id (:user_id user)}})
        {:status 401
         :body {:error "log in error"
                :message "Wrong password"}}))))

(defn post-logout [_]
  (redirect "/"))

(defn register-user [{{:keys [username password]} :body-params}]
  (if (or
       (nil? username)
       (nil? password)
       (= (count username) 0)
       (= (count password) 0))
    {:status 400
     :body {:error "sign up error"
            :message "invalid parameters.."}}
    (try (let [user (create-user {:name username
                                  :passwd password})
               token (create-token {:user (:user_id user)})]
           (response {:token token
                      :user_id (:user_id user)}))
         (catch java.sql.SQLException e {:status 400
                                         :body {:error "user creation error"
                                                :message (.getMessage e)}})
         (catch Exception e {:status 418
                             :body {:error "internal wtf"
                                    :message (.getMessage e)}}))))

(comment

  (register-user {:body-params {:username "user"
                                :password "user"}})
  (def user {:user_id 1
             :name "user"
             :passwd "bcrypt+sha512$4aa27ce2aeaf1662d1a2af48c70151db$12$cc252628f4c77d39c5d8f939c14f57dd65d9ee9ed677638b"})
  (def name (:name user))
  (def passwd (:passwd user))
  (users-db/get-user-by-name db-cfg {:name name})
  (users-db/list-users db-cfg {:user-fields (users-db/user-fields)})

  (def quotes (filter
               (fn [q] (not= (:is_private q) true))
               (quotes-db/list-quotes db-cfg {:quote-fields (quotes-db/quote-fields)})))

  (let [quotes (quotes-db/list-quotes db-cfg {:quote-fields (quotes-db/quote-fields)})
        public (filter (fn [q] (not= (:is_private q) true)) quotes)]
    {:status 200
     :body public})

  (quotes-db/create-quote
   db-cfg
   {:title "Title"
    :author "@author"
    :text "Big text"
    :is_private false
    :user_id 1}))