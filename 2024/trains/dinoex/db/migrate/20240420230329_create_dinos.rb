class CreateDinos < ActiveRecord::Migration[7.1]
  def change
    create_table :dinos do |t|
      t.string :name
      t.string :description
      t.string :image
      t.boolean :allowed
    end
  end
end
