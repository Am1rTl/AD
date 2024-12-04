{:store :database
 :migration-dir "migrations"
 :exclude-scripts ["*.clj"]
 :db {:dbtype "postgresql"
      :dbname (get (System/getenv) "DATABASE_DB" "ctf")
      :host (get (System/getenv) "DATABASE_HOST" "127.0.0.1")
      :user (get (System/getenv) "DATABASE_USER" "ctf")
      :password (get (System/getenv) "DATABASE_PASS" "ctf")}}
