class User < ActiveRecord::Base
    validates :username, presence: true
    validates :password, presence: true
    validates :secret, presence: true
    validates :fio, presence: true
   
    def self.register(username, password, secret, fio)
       user = User.new(username: username, password: password, secret: secret, fio: fio)
       user.save
       return user
    end

    def self.check_user_existence(username)
      User.where(username: username).find_each do |user|
        if (user)
          return user
        else
          return nil
        end
      end
    end
   
    def self.authenticate(username, password)
       User.where(username: username).find_each do |user|
         if (user && user.password == password)
           return user
         else
           return nil
         end
       end
    end
   
    def self.secret_check(username, secret)
      User.where(username: username).find_each do |user|
        if (user && user.secret == secret)
          return user
        else
          return nil
        end
      end
    end
   
    def self.reset(username, newPassword)
       User.where(username: username).find_each do |user|
         user.password = newPassword
         user.save
       end
    end

    def self.get_user_info(username)
      user = User.where(username: username) 
      return user
    end

    def self.change_profile_data(username, password, secret, fio, username2)
      User.where(username: username).find_each do |user|
        user.password = password
        user.secret = secret
        user.fio = fio
        user.username = username2
        user.save
      end
        return true
      end
end
   