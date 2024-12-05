require 'sinatra'

class DinoApp < Sinatra::Base
  get("/") { erb :index, :layout => :main, :locals => { :title => "Главная" }}
  get("/login") { erb :login, :layout => :main, :locals => { :title => "Логин" }}
  get("/register") { erb :register, :layout => :main, :locals => { :title => "Регистрация" }}
  get("/reset") { erb :reset, :layout => :main, :locals => { :title => "Сброс пароля" }}
  get("/dinos") { erb :dinos, :layout => :main, :locals => { :title => "Динозавры" }}
  get("/profile") { erb :profile, :layout => :main, :locals => { :title => "Профиль" }}
  get("/dino") { erb :dino, :layout => :main, :locals => { :title => "Динозавр", :id =>params[:id]} }
  get("/ticket") { erb :ticket, :layout => :main, :locals => { :title => "Билет", :id => params[:id]} }
  get("/buy") { erb :buy, :layout => :main, :locals => { :title => "Купить Билет" }}
  get("/logout") { redirect "/api/users/logout" }

  def current_user
    begin
    username = username_from_jwt request.cookies['token']
    @current_user ||= User.find_by(username: username)
    rescue => e
      return nil
    end
  end
end
