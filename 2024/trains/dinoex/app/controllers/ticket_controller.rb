require 'jwt'
require 'sinatra'
require 'json'

enable :sessions

class TicketController < DinoApp
  get '/view-ticket' do
    ticketId = params['ticketId']
    username = username_from_jwt request.cookies['token']
    ticket = Ticket.check_ownership(ticketId, username)

    if ticket
      ticket = Ticket.get_ticket_information(ticketId, username)
      return ticket.to_json
    end

    status 401
  end

  get '/get-user-tickets' do
    username = username_from_jwt request.cookies['token']
    tickets = Ticket.get_user_tickets(username)
    tickets.to_json
  end

  post "/buy-ticket" do
    username = username_from_jwt request.cookies['token']
    secret_word = params['secret_word']
    fio = params['fio']
    date = params['date']
    ticket = Ticket.buy(username, secret_word, date, fio)

    if ticket
      show = Users_verified.add(username, ticket)
      return show.to_json
    end
    
    status 500
  end

  get '/forced-view' do
    if request.query_string.include?("&")
      status 403
      return nil
    end
    
    ticketId = params['ticketId']
    username = params['username']    
    ticket = Ticket.get_ticket_information(ticketId, username)
    ticket.to_json
  end
end
