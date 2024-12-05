class Ticket < ActiveRecord::Base
    validates :username, presence: true
    validates :secret_word, presence: true
    validates :date_string, presence: true
    validates :fio, presence: true
   
    def self.check_ownership(ticketId, username)
        Ticket.where(id: ticketId).find_each do |ticket|
            if (ticket && ticket.username == username)
                return ticket
            else
                return nil
            end
        end
    end
    
    def self.buy(username, secret_word, date, fio)
        ticket = Ticket.new(username: username, secret_word: secret_word, date_string: date, fio: fio)
        ticket.save
        return ticket.id
      end

    def self.get_ticket_information(ticketId, username)
        ticket = Ticket.where(id: ticketId, username: username) 
        return ticket
    end

    def self.get_user_tickets(username)
        ticket = Ticket.where(username: username)
        puts ticket
        return ticket
    end    
end
