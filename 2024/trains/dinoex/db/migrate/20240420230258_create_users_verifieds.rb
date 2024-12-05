class CreateUsersVerifieds < ActiveRecord::Migration[7.1]
  def change
    create_table :users_verifieds do |t|
      t.string :username
      t.integer :ticketId
    end
  end
end
