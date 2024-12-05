(ns backend.db.users
  (:require
   [hugsql.core :as hugsql]))

(declare user-fields list-users get-user-by-id get-user-by-name create-user)

(hugsql/def-db-fns "sql/users.sql")
