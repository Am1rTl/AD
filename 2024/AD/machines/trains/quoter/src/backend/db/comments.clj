(ns backend.db.comments
  (:require [hugsql.core :as hugsql]))

(declare comment-fields
         only-comment-fields
         list-comments
         get-comment-by-id
         create-comment
         get-comments-by-quote-id
         only-comment-fields
         delete-comment-by-id)

(hugsql/def-db-fns "sql/comments.sql")

(comment
  (def db-cfg {:classname "org.postgresql.Driver"
               :subprotocol "postgresql"
               :subname "//127.0.0.1:5432/ctf"
               :user "ctf"
               :password "ctf"})

  (get-comments-by-quote-id db-cfg {:quote_id 2
                                    :comment-fields (only-comment-fields)})
  (list-comments db-cfg {:comment-fields (comment-fields)})

  (get-comment-by-id db-cfg {:id 2
                             :comment-fields (comment-fields)}))