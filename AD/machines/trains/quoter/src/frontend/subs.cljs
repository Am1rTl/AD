(ns frontend.subs
  (:require
   [re-frame.core :as re-frame]))

(re-frame/reg-sub
 ::login-form-status
 (fn [db]
   (:status (:login-form db))))

(re-frame/reg-sub
 ::signup-form-status
 (fn [db]
   (:status (:login-form db))))

(re-frame/reg-sub
 ::auth-token
 (fn [db]
   (:token db)))

(re-frame/reg-sub
 ::active-panel
 (fn [db _]
   (get-in db [:route :panel])))

(re-frame/reg-sub
 ::route-params
 (fn [db _]
   (get-in db [:route :route :route-params])))