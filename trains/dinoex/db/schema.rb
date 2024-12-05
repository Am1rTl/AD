ActiveRecord::Schema[7.1].define(version: 2024_04_20_230354) do
  
  enable_extension "plpgsql"

  create_table "dinos", force: :cascade do |t|
    t.string "name"
    t.string "description"
    t.string "image"
    t.boolean "allowed"
  end

  create_table "tickets", force: :cascade do |t|
    t.string "fio"
    t.string "date_string"
    t.string "secret_word"
    t.string "username"
  end

  create_table "users", force: :cascade do |t|
    t.string "username"
    t.string "password"
    t.string "secret"
    t.string "fio"
  end

  create_table "users_verifieds", force: :cascade do |t|
    t.string "username"
    t.integer "ticketId"
  end

end
