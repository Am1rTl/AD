(ns backend.core
  (:require
   [backend.auth :refer [wrap-jwt-authentication auth-middleware]]
   [backend.db.migrations :as migrations]
   [backend.handler :as handlers]
   [clojure.java.io :as io]
   [expound.alpha :as expound]
   [mount.core :as mount]
   [muuntaja.core :as m]
   [reitit.coercion.spec]
   [reitit.core :as r]
   [reitit.ring :as ring]
   [reitit.ring.coercion :as coercion]
   [reitit.ring.middleware.exception :as r-exception]
   [reitit.ring.middleware.muuntaja :as muuntaja]
   [reitit.ring.middleware.parameters :as parameters]
   [ring.adapter.jetty :as ring-jetty]
   [ring.util.response :refer [redirect]])
  (:gen-class))

(defn coercion-error-handler [status]
  (let [printer (expound/custom-printer {:theme :figwheel-theme,
                                         :print-specs? false})
        handler (r-exception/create-coercion-handler status)]
    (fn [exception request]
      (printer (-> exception ex-data :problems))
      (handler exception request))))

(def authenticated-middleware [wrap-jwt-authentication auth-middleware])

(def creds-body-valid {:username string?
                       :password string?})

(def quote-body-valid {:title string?
                       :author string?
                       :text string?
                       :is_private boolean?})

(def app-router (ring/router
                 ["/"
                  ["" {:handler (fn [_] {:body (slurp (io/resource "public/index.html"))
                                         :status 200})}]
                  ["js/*" (ring/create-resource-handler {:root "public/js"})]
                  ["assets/*" (ring/create-resource-handler {:root "public/assets"})]
                  ["favicon.ico" {:handler (fn [_] (redirect "/assets/favicon.ico"))}]
                  ["api/"
                   ["healthcheck" {:middleware []
                                   :handler handlers/healthcheck}]
                   ["signup" {:post {:middleware []
                                     :parameters {:body creds-body-valid}
                                     :handler handlers/register-user}}]
                   ["login" {:post {:parameters {:body creds-body-valid}
                                    :handler handlers/post-login}}]
                   ["logout" {:post {:middleware authenticated-middleware
                                     :handler handlers/post-logout}}]

                   ["users"
                    ["/" {:get handlers/get-users}]
                    ["/:id" {:get {:middleware authenticated-middleware
                                   :handler handlers/get-user-by-id
                                   :parameters {:path {:id int?}}}}]]

                   ["quotes" {:middleware authenticated-middleware}
                    ["/mine" {:get {:middleware authenticated-middleware
                                    :handler handlers/get-my-quotes}}]
                    ["/" {:get {:handler handlers/get-quotes}
                          :post {:parameters {:body quote-body-valid}
                                 :handler handlers/create-quote}}]
                    ["/:id" ["/" {:get {:handler handlers/get-quote-by-id
                                        :parameters {:path {:id int?}}}}]
                     ["/comments" {:get {:handler handlers/get-comments-of-quote}
                                   :post {:handler handlers/create-comment-for-quote}}]]]

                   ["comments"
                    ["/" {:get {:handler handlers/get-all-nonprivate-comments}}]
                    ["/:id" {:get {:middleware authenticated-middleware
                                   :handler handlers/get-comment-by-id
                                   :parameters {:path {:id int?}}}}]]]]

                 {:data {:coercion reitit.coercion.spec/coercion
                         :muuntaja m/instance
                         :middleware [muuntaja/format-middleware
                                      parameters/parameters-middleware
                                      (r-exception/create-exception-middleware
                                       (merge
                                        r-exception/default-handlers
                                        coercion/coerce-exceptions-middleware))
                                      coercion/coerce-request-middleware]}}))

(def app
  (-> app-router
      (ring/ring-handler (ring/routes
                          (ring/redirect-trailing-slash-handler)
                          (ring/create-default-handler
                           {:not-found (constantly {:status 404
                                                    :body "Not found"})
                            :method-not-allowed (constantly {:status 405})
                            :not-acceptable (constantly {:status 406})})))))

(defn start []
  (ring-jetty/run-jetty #'app {:port 3000
                               :send-server-version? false
                               :output-buffer-size 49152
                               :join? false}))

(mount/defstate server
  :start (start)
  :stop (.stop server))

(defn -main []
  (if (not (nil? (get (System/getenv) "PRODUCTION")))
    (do (print "Doing migrations...")
        (migrations/migrate))
    (print "Skipping migrations..."))
  (print "Starting server...")
  (mount/start))

(comment
  (mount/stop)
  (mount/start)

  (-> app (ring/get-router) (r/match-by-path "/healthcheck"))
  (r/match-by-path app-router "/healthcheck")

  (app {:request-method :get
        :uri "/api/healthcheck"})

  (app {:request-method :get
        :uri "/"})

  (def r (app {:request-method :post
               :uri "/api/login"
               :body-params {:username "katok"
                             :password "katok"}}))

  ;; function that takes body which contains json and decode it to map
  (defn decode [body]
    (-> body
        (slurp)
        (cheshire.core/parse-string true)))

  (def decoded (decode (:body r)))

  (:token decoded)

  (let [response (app {:headers {"authorization" (str "Token " (:token decoded))}
                       :request-method :get
                       :uri "/api/quotes/"})
        decoded-r (decode (:body response))]
    (print decoded-r)))