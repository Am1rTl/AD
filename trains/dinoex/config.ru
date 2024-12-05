require 'bundler'
Bundler.require

require File.expand_path('../config/environment',  __FILE__)

require_relative 'lib/sinatra/custom_param_middleware'

app = Rack::Builder.new do
  use CustomParamMiddleware
  
  map("/api/dino") {run DinoController}
  map("/api/users") {run UsersController}
  map("/api/ticket") {run TicketController}
  map("/") {run DinoApp}
end

run app
