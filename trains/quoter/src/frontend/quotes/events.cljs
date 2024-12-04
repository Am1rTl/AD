
(ns frontend.quotes.events
  (:require
   [ajax.core :as ajax]
   [day8.re-frame.http-fx]
   [day8.re-frame.tracing :refer-macros [fn-traced]]
   [frontend.events :as events]
   [re-frame.core :as re-frame]))

(def resp-format (ajax/json-response-format {:keywords? true}))

;; Get list of quotes

(re-frame/reg-event-fx
 ::fetch-quotes
 (fn-traced [{:keys [db]} _]
            {:db (assoc db :loading true)
             :http-xhrio {:method :get
                          :uri "/api/quotes"
                          :format (ajax/json-request-format)
                          :timeout 8000
                          :headers {:authorization (str "Token " (:token db))}
                          :response-format resp-format
                          :on-success [::fetch-quotes-ok]
                          :on-failure [::fetch-quotes-suck]}}))

(re-frame/reg-event-db
 ::fetch-quotes-suck
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:xhr-request] result))))

(re-frame/reg-event-db
 ::fetch-quotes-ok
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:xhr-request] result)
                (assoc :quotes (vec result)))))

;; GET QUOTE BY ID

(re-frame/reg-event-fx
 ::fetch-quote-comments
 (fn-traced [{:keys [db]} [_ quote-info]]
            (let [quote-id (js/parseInt (:quote-id quote-info))]
              {:db (assoc db :loading true)
               :http-xhrio {:method :get
                            :uri (str "/api/quotes/" quote-id "/comments")
                            :format (ajax/json-request-format)
                            :timeout 8000
                            :headers {:authorization (str "Token " (:token db))}
                            :response-format resp-format
                            :on-success [::fetch-quote-comments-ok {:quote-id quote-id}]
                            :on-failure [::fetch-quote-comments-suck]}})))

(re-frame/reg-event-db
 ::fetch-quote-comments-suck
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:xhr-request] result))))

(re-frame/reg-event-db
 ::fetch-quote-comments-ok
 (fn-traced [db [_ quote-info result]]
            (let [comments (:comments result)
                  quote-id (:quote-id quote-info)]
              (-> db
                  (assoc :loading false)
                  (assoc-in [:xhr-request] result)
                  (update-in [:quotes] (fn [quotes]
                                         (vec (map (fn [quote]
                                                     (if (= (:quote_id quote) quote-id)
                                                       (assoc quote :comments comments)
                                                       quote)) quotes))))))))

;; Comments of quotes

(defn find-index-of-quote [lst val]
  (first (keep-indexed #(when (= (get %2 :quote_id) val) %1) lst)))

;; Client Side Path Traversal ???
(re-frame/reg-event-fx
 ::submit-comment
 (fn-traced [{:keys [db]} [_ quote-info]]
            (let [quote-id (js/parseInt (:quote-id quote-info))]
              {:db (assoc db :loading true)
               :http-xhrio {:method :post
                            :uri (str "/api/quotes/" quote-id "/comments")
                            :params {:comment (get-in db [:comment-form :payload :comment])}
                            :format (ajax/json-request-format)
                            :timeout 8000
                            :headers {:authorization (str "Token " (:token db))}
                            :response-format resp-format
                            :on-success [::submit-comment-ok (find-index-of-quote (:quotes db) quote-id)]
                            :on-failure [::submit-comment-suck]}})))

(re-frame/reg-event-db
 ::submit-comment-suck
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:xhr-request] result))))

(re-frame/reg-event-db
 ::submit-comment-ok
 (fn-traced [db [_ quote-id result]]
            (let [new-comment (dissoc (:comment result) :user_id :quote_id)]

              (-> db
                  (assoc :loading false)
                  (assoc-in [:xhr-request] new-comment)
                  (update-in [:quotes quote-id :comments] conj new-comment)))))

(re-frame/reg-event-fx
 ::create-quote
 (fn-traced [{:keys [db]} _]
            {:db (assoc db :loading true)
             :http-xhrio {:method :post
                          :uri "/api/quotes"
                          :format (ajax/json-request-format)
                          :params (get-in db [:quote-form :payload])
                          :timeout 8000
                          :headers {:authorization (str "Token " (:token db))}
                          :response-format resp-format
                          :on-success [::create-quote-ok]
                          :on-failure [::create-quote-suck]}}))

(re-frame/reg-event-db
 ::update-quote-form
 (fn-traced [db [_ id value]]
            (assoc-in db [:quote-form :payload id] value)))

(re-frame/reg-event-db
 ::update-comment-form
 (fn-traced [db [_ id value]]
            (assoc-in db [:comment-form :payload id] value)))

(re-frame/reg-event-db
 ::create-quote-suck
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:quote-form :status] result)
                (assoc-in [:xhr-request] result))))

(re-frame/reg-event-db
 ::create-quote-ok
 (fn-traced [db [_ result]]
            (re-frame/dispatch [::events/navigate [:quotes-list]])
            (-> db
                (assoc :loading false)
                (assoc-in [:xhr-request] result)
                (update-in [:quotes] result))))

(comment
  (def db {:quotes
           [{:title 1}
            {:title 2}]})

  (print @db)

  (update db :quotes conj {:title 3}))