-- :snip user-fields
user_id, name

-- :name list-users :?
select :snip:user-fields from users 
order by user_id;

-- :name get-user-by-id :? :1
select :snip:user-fields from users
where user_id = :id;

-- :name get-user-by-name :? :1
select * from users
where name = :name;

-- :name create-user :i!
insert into users (name, passwd)
values (:name, :passwd);

-- :name delete-user-by-name :! :n
DELETE FROM users 
WHERE name = :name;