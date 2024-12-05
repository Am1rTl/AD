(ns frontend.users.views
  (:require
   [frontend.events :as events]
   [frontend.routes :as routes]
   [frontend.users.subs :as user-subs]
   [re-frame.core :as re-frame]))

(defn load-users []
  (re-frame/dispatch [::events/fetch-users]))

(defn display-users [users]
  [:div
   [:ol
    (map (fn [user] [:li {:user_id (:user_id user)} (:name user)]) users)]])

(defn users-list []
  (load-users)
  (let [users @(re-frame/subscribe [::user-subs/users])]
    [:div.users-list
     [:h3 "List of users!"]
     (display-users users)]))

(defmethod routes/panels :users-list-panel [] [users-list])

(comment
  (display-users [{:name "katok"
                   :user-id 1}]))