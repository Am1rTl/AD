(ns frontend.views
  (:require
   [frontend.events :as events]
   [frontend.routes :as routes]
   [frontend.subs :as subs]
   [re-frame.core :as re-frame]))

;; log in

(defn login-form-updater [key]
  #(re-frame/dispatch [::events/update-login-form key (-> % .-target .-value)]))

(defn login-panel []
  (let [login-form-status (re-frame/subscribe [::subs/login-form-status])]
    [:div.loginpanel
     [:h2 "enter your creds to log in"]
     [:div [:label
            [:input {:on-change (login-form-updater :username)
                     :type "text"
                     :name "login"
                     :placeholder "Username"}]]]
     [:div [:label
            [:input {:on-change (login-form-updater :password)
                     :type "password"
                     :name "login"
                     :placeholder "Password"}]]]
     [:button {:on-click #(re-frame/dispatch [::events/login])} "Login"]
     [:div.status
      [:div (:status @login-form-status)]
      [:div (:status-text @login-form-status)]]]))

(defmethod routes/panels :login-panel [] [login-panel])

;; sing up

(defn signup-form-updater [key]
  #(re-frame/dispatch [::events/update-signup-form key (-> % .-target .-value)]))

(defn signup-panel []
  (let [form-status (re-frame/subscribe [::subs/signup-form-status])]
    [:div.signuppanel

     [:h2 "enter your creds to register"]
     [:div [:label
            [:input {:on-change (signup-form-updater :username)
                     :type "text"
                     :name "login"
                     :placeholder "Username"}]]]
     [:div [:label
            [:input {:on-change (signup-form-updater :password)
                     :type "password"
                     :name "login"
                     :placeholder "Password"}]]]
     [:button {:on-click #(re-frame/dispatch [::events/signup])} "Sign up"]
     [:div.status
      [:div (:status @form-status)]
      [:div (:status-text @form-status)]]]))

(defmethod routes/panels :signup-panel [] [signup-panel])

;; home

(defn home-panel []
  (let [token (re-frame/subscribe [::subs/auth-token])]
    [:div.homepanel
     [:h3
      (str "Hello ! This is the Home Page. ")]

     [:div
      [:a {:on-click #(re-frame/dispatch [::events/navigate [:login]])}
       "Log in"]]
     [:div
      [:a {:on-click #(re-frame/dispatch [::events/navigate [:signup]])}
       "Sign up"]]
     [:div
      [:a {:on-click #(re-frame/dispatch [::events/navigate [:users-list]])}
       "Users here"]]
     (if (seq @token)
       [:div
        [:a {:on-click #(re-frame/dispatch [::events/navigate [:quotes-list]])}
         "Quotes here"]])]))

(defmethod routes/panels :home-panel [] [home-panel])

;; main

(defn main-panel []
  (let [active-panel (re-frame/subscribe [::subs/active-panel])]
    [:div
     [:a {:on-click #(re-frame/dispatch [::events/navigate [:home]])} [:h1 "Welcome to " [:label "Quoter"]]]

     [:img {:src "/assets/quoter.gif"}]
     [:div.app (routes/panels @active-panel)]]))

(comment

  (if (seq "string")
    [:div
     [:a {:on-click #(re-frame/dispatch [::events/navigate [:quotes-list]])}
      "Quotes here"]]
    [:div "Noting here"])

  (home-panel))