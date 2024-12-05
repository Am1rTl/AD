-- :snip only-comment-fields
comment_id, comment

-- :snip comment-fields
comment_id, comment, quote_id, user_id

-- :name list-comments :?
select :snip:comment-fields from comments 
order by comment_id;

-- :name get-comment-by-id :? :1 
select :snip:comment-fields from comments 
where comment_id = :id;

-- :name get-comments-by-quote-id :?
select :snip:comment-fields from comments 
where quote_id = :quote_id;

-- :name create-comment :i!
insert into comments (comment, user_id, quote_id)
values (:comment, :user_id, :quote_id);

-- :name delete-comment-by-id :! :1
DELETE FROM comments 
WHERE comment_id = :id;