database_name = "dino-#{DinoApp.environment}"

ActiveRecord::Base.establish_connection(
  adapter:    'postgresql',
  host:       'db',
  database:   'postgres',
  username:   ENV['BD_Username'],
  password:   ENV['BD_Password'],
  port:       ENV['BD_Port']
)