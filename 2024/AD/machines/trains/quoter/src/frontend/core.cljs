(ns frontend.core
  (:require
   [frontend.config :as config]
   [frontend.events :as events]
   [frontend.quotes.subs]
   [frontend.quotes.views]
   [frontend.routes :as routes]
   [frontend.users.subs]
   [frontend.users.views]
   [frontend.views :as views]
   [re-frame.core :as re-frame]
   [reagent.dom :as rdom]))

(defn dev-setup []
  (when config/debug?
    (println "dev mode")))

(defn ^:dev/after-load mount-root []
  (re-frame/clear-subscription-cache!)
  (let [root-el (.getElementById js/document "app")]
    (rdom/unmount-component-at-node root-el)
    (rdom/render [views/main-panel] root-el)))

(defn init []
  (routes/start!)
  (re-frame/dispatch-sync [::events/initialize-db])
  (dev-setup)
  (mount-root))
