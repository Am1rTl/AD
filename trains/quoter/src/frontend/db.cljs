(ns frontend.db)

(def default-db
  {:login-form
   {:payload {:username ""
              :password ""}}
   :signup-form
   {:payload {:username ""
              :password ""}}

   :quote-form
   {:payload {:is_private false}}
   :users-view {}
   :quotes-view {}
   :loading false
   :users []
   :quotes []
   :my-id 1
   :token ""})