(ns frontend.routes
  (:require
   [bidi.bidi :as bidi]
   [frontend.events :as events]
   [pushy.core :as pushy]
   [re-frame.core :as re-frame]))

(defmulti panels identity)
(defmethod panels :default [] [:div "No panel found for this route."])

(def routes
  (atom
   ["/" {"" :home
         "login" :login
         "signup" :signup
         "quotes" {"" :quotes-list
                   "/create" :quote-create
                   ["/" :id] :quote-view}
         "users" {"" :users-list
                  ["/" :id] :user-view}}]))

(defn parse
  [url]
  (bidi/match-route @routes url))

(defn url-for
  [& args]
  (apply bidi/path-for (into [@routes] args)))

(defn dispatch
  [route]
  (let [panel (keyword (str (name (:handler route)) "-panel"))]
    #_(re-frame/dispatch [::events/set-active-panel panel])
    (re-frame/dispatch [::events/set-route {:route route
                                            :panel panel}])))

(defonce history
  (pushy/pushy dispatch parse))

(defn navigate!
  [handler]
  (pushy/set-token! history (apply url-for handler)))

(defn start!
  []
  (pushy/start! history))

(re-frame/reg-fx
 :navigate
 (fn [handler]
   (navigate! handler)))

(comment
  (navigate! [:login-panel])

  (parse "/login")
  (url-for :login)

  (keyword (str (name (:handler (parse "/login"))) "-panel"))

  (parse "/quotes/create")
  (url-for :quote-create)
  ;; (url-for :quote-create {:id 1})

  ; check which panel to create  *here your panel*
  (keyword (str (name (:handler (parse "/quotes/create"))) "-panel")))