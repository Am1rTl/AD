(ns frontend.events
  (:require
   [ajax.core :as ajax]
   [day8.re-frame.http-fx]
   [day8.re-frame.tracing :refer-macros [fn-traced]]
   [frontend.db :as db]
   [re-frame.core :as re-frame]))

;; init / funcs

(def resp-format (ajax/json-response-format {:keywords? true}))

(re-frame/reg-event-db
 ::initialize-db
 (fn-traced [_ _]
            db/default-db))

;; ---

; Live updating of forms value

(re-frame/reg-event-db
 ::update-login-form
 (fn-traced [db [_ id value]]
            (assoc-in db [:login-form :payload id] value)))

(re-frame/reg-event-db
 ::update-signup-form
 (fn-traced [db [_ id value]]
            (assoc-in db [:signup-form :payload id] value)))

;; ---

; AJAX requests and handlers

(re-frame/reg-event-fx
 ::fetch-users
 (fn-traced [{:keys [db]} _]
            {:db (assoc db :loading true)
             :http-xhrio {:method :get
                          :uri "/api/users"
                          :format (ajax/json-request-format)
                          :timeout 8000
                          :response-format resp-format
                          :on-success [::fetch-users-ok]
                          :on-failure [::fetch-users-suck]}}))

(re-frame/reg-event-db
 ::fetch-users-suck
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:users-view :status] result))))

(re-frame/reg-event-db
 ::fetch-users-ok
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:users-view :status] result)
                (assoc :users result))))

(re-frame/reg-event-fx
 ::login
 (fn-traced [{:keys [db]} _]
            {:db (assoc db :loading true)
             :http-xhrio {:method :post
                          :uri "/api/login"
                          :params (get-in db [:login-form :payload])
                          :format (ajax/json-request-format)
                          :timeout 8000
                          :response-format resp-format
                          :on-success [::login-form-succsess]
                          :on-failure [::login-form-suck]}}))

(re-frame/reg-event-fx
 ::signup
 (fn-traced [{:keys [db]} _]
            {:db (assoc db :loading true)
             :http-xhrio {:method :post
                          :uri "/api/signup"
                          :params (get-in db [:signup-form :payload])
                          :format (ajax/json-request-format)
                          :timeout 8000
                          :response-format resp-format
                          :on-success [::login-form-succsess]
                          :on-failure [::signup-form-suck]}}))

(re-frame/reg-event-db
 ::signup-form-suck
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:signup-form :status] result))))

(re-frame/reg-event-db
 ::login-form-suck
 (fn-traced [db [_ result]]
            (-> db
                (assoc :loading false)
                (assoc-in [:login-form :status] result))))

(re-frame/reg-event-db
 ::login-form-succsess
 (fn-traced [db [_ result]]

            (re-frame/dispatch [::navigate [:home]])
            (-> db
                (assoc :loading false)
                (assoc :token (:token result))
                (assoc :my-id (:user_id result)))))

;; ---

; Navigation

(re-frame/reg-event-fx
 ::navigate
 (fn-traced [_ [_ handler]]
            {:navigate handler}))

(re-frame/reg-event-fx
 ::set-active-panel
 (fn-traced [{:keys [db]} [_ active-panel]]
            {:db (assoc db :active-panel active-panel)}))

(re-frame/reg-event-fx
 ::set-route
 (fn-traced [{:keys [db]} [_ route]]
            {:db (assoc db :route route)}))

;; ---