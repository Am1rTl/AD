CREATE TABLE users(
  user_id SERIAL PRIMARY KEY,
  name varchar ( 50) not null unique,
  passwd varchar (120) not null
);

--;;

CREATE INDEX idx_users_name ON users(name);

--;;

CREATE TABLE quotes(
  quote_id SERIAL PRIMARY KEY,
  title varchar ( 50) not null,
  author varchar ( 50) not null,
  text varchar (256) not null,
  is_private BOOLEAN DEFAULT FALSE NOT NULL,
  user_id INT,
  CONSTRAINT fk_user  FOREIGN KEY(user_id) REFERENCES users(user_id)
);

--;;

CREATE INDEX idx_quotes_title ON quotes(user_id);

--;;

CREATE TABLE comments(
  comment_id SERIAL PRIMARY KEY,
  comment varchar (256) not null,
  user_id INT not null,
  quote_id INT not null,
  CONSTRAINT fk_user  FOREIGN KEY(user_id) REFERENCES users(user_id),
  CONSTRAINT fk_quote  FOREIGN KEY(quote_id) REFERENCES quotes(quote_id)
);