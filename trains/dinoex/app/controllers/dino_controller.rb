require 'sinatra'
require 'open-uri'

class DinoController < DinoApp
  get '/' do
    dino = Dino.get(params)
  
    if dino
      content_type :json
      return dino.to_json
    end

    status 200
  end

  get '/all' do
    dinos = Dino.get_all

    dinos.to_json
  end
end
