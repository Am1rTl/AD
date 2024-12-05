(ns frontend.quotes.views
  (:require
   [frontend.events :as events]
   [frontend.quotes.events :as q-events]
   [frontend.quotes.subs :as q-subs]
   [frontend.routes :as routes]
   [frontend.subs :as subs]
   [re-frame.core :as re-frame]))

(defn display-quotes [quotes]
  [:div
   [:ol
    (map (fn [quote]
           [:li {:key (:quote_id quote)
                 :on-click #(re-frame/dispatch [::events/navigate [:quote-view {:id (:quote_id quote)}]])}
            (str (:title quote)
                 " by " (:author quote))]) quotes)]])

(defn quotes-list []
  (let [token @(re-frame/subscribe [::subs/auth-token])]
    [:div.quotes-list
     [:h3 "List of quotes"]
     [:button {:on-click #(re-frame/dispatch [::events/navigate [:quote-create]])} "create your quote"]
     (if (seq token)
       (let [quotes @(re-frame/subscribe [::q-subs/quotes])]
         (re-frame/dispatch [::q-events/fetch-quotes])
         (display-quotes quotes))
       [:h5 "Log in first"])]))

(defmethod routes/panels :quotes-list-panel [] [quotes-list])

(defn quote-view []
  (let [quote-id (:id @(re-frame/subscribe [::subs/route-params]))
        quote @(re-frame/subscribe [::q-subs/quote-by-id {:id quote-id}])]
    (re-frame/dispatch [::q-events/fetch-quote-comments {:quote-id quote-id}])
    [:div.quote

     [:div
      [:h3 (str (:quote_id quote) ". " (:title quote))]
      [:h4 "by " (:author quote)]
      [:p (:text quote)]

      (when-let [comments (:comments quote)]
        (for [comment comments]
          (let [id (:comment_id comment)]
            [:p {:key id} (str id ". " (:comment comment))])))]

     [:label
      [:textarea {:on-change #(re-frame/dispatch [::q-events/update-comment-form :comment (-> % .-target .-value)])
                  :placeholder "Your comment"}]
      [:input {:on-click #(re-frame/dispatch [::q-events/submit-comment {:quote-id quote-id}])
               :type "submit"
               :value "Submit"}]]]))

(defmethod routes/panels :quote-view-panel [] [quote-view])

(defn quote-form-updater [key]
  #(re-frame/dispatch [::q-events/update-quote-form key (-> % .-target .-value)]))

(defn quote-create []
  (let [#_#_login-form-status (re-frame/subscribe [::subs/login-form-status])]
    [:div.quote-create-panel
     [:h2 "Enter data about your quote"]

     [:div [:label
            [:input {:on-change (quote-form-updater :title)
                     :type "text"
                     :name "title"
                     :placeholder "Title"}]]]

     [:div [:label
            [:input {:on-change (quote-form-updater :author)
                     :type "text"
                     :name "author"
                     :placeholder "Author"}]]]

     [:div [:label
            [:input {:on-change (quote-form-updater :text)
                     :type "text"
                     :name "text"
                     :placeholder "Your quote"}]]]
     [:div [:label
            [:input {:on-change #(re-frame/dispatch [::q-events/update-quote-form :is_private (-> % .-target .-checked)])
                     :type "checkbox"
                     :name "private"}]
            " Private"]]

     [:button {:on-click #(re-frame/dispatch [::q-events/create-quote])} "Create"]
     [:div.status]]))

(defmethod routes/panels :quote-create-panel [] [quote-create])

(comment

  (js/console.log "hi")

  (js/fetch (str "http://" "localhost:8280/" "api/users")))