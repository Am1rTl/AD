(ns backend.db.quotes
  (:require [hugsql.core :as hugsql]))

(declare create-quotes-table
         quote-fields
         list-quotes
         get-quote-by-user-id
         get-quote-by-id
         create-quote)

(hugsql/def-db-fns "sql/quotes.sql")