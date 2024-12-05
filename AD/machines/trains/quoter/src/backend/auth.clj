(ns backend.auth
  (:require [buddy.auth :refer [authenticated?]]
            [buddy.auth.backends :as backends]
            [buddy.auth.middleware :refer [wrap-authentication]]
            [buddy.hashers :as hashers]
            [buddy.sign.jwt :as jwt]))

(defonce jwt-secret '(java.util.UUID/randomUUID))

(defn get-jwtsecret []
  (str jwt-secret))

(def backend (backends/jws {:secret (get-jwtsecret)}))

(defn wrap-jwt-authentication
  [handler]
  (wrap-authentication handler backend))

;; TODO: vuln or not?
(defn authenticated [request]
  (empty? (get-in request [:headers "authorization"])))

(defn auth-middleware
  [handler]
  (fn [request]
    (if (authenticated? request)
      (handler request)
      {:status 401
       :body {:error "Unauthorized"}})))

(defn create-token [payload]
  (jwt/sign payload (get-jwtsecret)))

(defn hash-passwd [password]
  (hashers/derive password {:alg :bcrypt+sha512}))

(defn verify-passwd [password hash]
  (:valid (hashers/verify password hash)))

(comment

  (jwt/unsign ""
              (get-jwtsecret))

  (create-token {:id 2}))