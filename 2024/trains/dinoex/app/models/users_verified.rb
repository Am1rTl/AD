class Users_verified < ActiveRecord::Base
    validates :ticketId, presence: true, uniqueness: true
    validates :username, presence: true
   
    def self.add(username, ticketId)
       user = Users_verified.new(username: username, ticketId: ticketId)
       user.save
       return user
    end
   
    def self.get_list()
        ticket = Users_verified.all
        return ticket.all
    end
end
