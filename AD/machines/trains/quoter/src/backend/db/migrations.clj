(ns backend.db.migrations
  (:require [migratus.core :as migratus]))

(def config {:store :database
             :migration-dir "migrations"
             :exclude-scripts ["*.clj"]
             :db {:dbtype "postgresql"
                  :dbname (get (System/getenv) "DATABASE_DB" "ctf")
                  :host (get (System/getenv) "DATABASE_HOST")
                  :user (get (System/getenv) "DATABASE_USER" "ctf")
                  :password (get (System/getenv) "DATABASE_PASS" "ctf")}})

;initialize the database using the 'init.sql' script
(defn init []
  (migratus/init config))

;apply pending migrations
(defn migrate []
  (migratus/migrate config))

;rollback the migration with the latest timestamp
(defn rollback []
  (migratus/rollback config))

;bring up migrations matching the ids
;; (migratus/up config 20111206154000)

;bring down migrations matching the ids
;; (migratus/down config 20111206154000)