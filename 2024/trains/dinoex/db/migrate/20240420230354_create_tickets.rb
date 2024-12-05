class CreateTickets < ActiveRecord::Migration[7.1]
  def change
    create_table :tickets do |t|
      t.string :fio
      t.string :date_string
      t.string :secret_word
      t.string :username
    end
  end
end
