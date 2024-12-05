(ns backend.db.db
  #_{:clj-kondo/ignore [:unused-namespace]}
  (:require [hugsql.core :as hugsql]))

(def db-cfg
  {:classname "org.postgresql.Driver"
   :subprotocol "postgresql"
   :subname (str "//" (get (System/getenv) "DATABASE_HOST" "127.0.0.1") ":5432/" (get (System/getenv) "DATABASE_DB" "ctf"))
   :user (get (System/getenv) "DATABASE_USER" "ctf")
   :password (get (System/getenv) "DATABASE_PASS" "ctf")})