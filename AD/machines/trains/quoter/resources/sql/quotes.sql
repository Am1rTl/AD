-- :snip quote-fields
quote_id, title, author, text, is_private, user_id

-- :name list-quotes :?
select :snip:quote-fields from quotes;

-- :name get-quote-by-id :? :1
select :snip:quote-fields from quotes
where quote_id = :id;

-- :name create-quote :i!
insert into quotes (title, author, text, is_private, user_id)
values (:title, :author, :text, :is_private, :user_id);

-- :name get-quote-by-user-id :?
select :snip:quote-fields from quotes
where user_id = :id;