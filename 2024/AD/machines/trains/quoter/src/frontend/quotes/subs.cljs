(ns frontend.quotes.subs
  (:require
   [re-frame.core :as re-frame]))

(re-frame/reg-sub
 ::quotes
 (fn [db _]
   (:quotes db)))

(re-frame/reg-sub
 ::quote-by-id
 (fn [db [_ id]]
   (let [id (js/parseInt (:id id))
         quotes (:quotes db)
         quote (filter #(= (:quote_id %) id) quotes)]
     (first quote))))