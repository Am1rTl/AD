require 'jwt'
require 'json'

class UsersController < DinoApp
    post '/register' do
        username = params[:username]
        password = params[:password]
        secret = params[:secret]
        fio = params[:fio]

        is_registered = User.check_user_existence(username)

        if is_registered != nil
            status 403
            return "This user is already registered"
        end

        user = User.register(username, password, secret, fio)

        if user
            status 200
            return "User registred"
        end

        status 500
        return "Something went wrong"
    end

    post '/login' do
        username = params[:username]
        password = params[:password]

        user = User.authenticate(username, password)
        if user
            headers['Set-Cookie'] = "token=#{jwt_from_username username}; path=/; HttpOnly"
            status 200
            return "User authenticated"
        end

        status 500
        return "Something went wrong"
    end

    post '/reset' do
        username = params[:username]
        secret = params[:secret]
        newPassword = params[:newPassword]

        user = User.secret_check(username, secret)
        if (user)
            User.reset(username, newPassword)
            status 200
            return ""
        end

        status 500
    end

    get '/logout' do
        headers['Set-Cookie'] = "token=; path=/; HttpOnly"
        redirect '/'
    end

    post '/profile-edit' do
        oldUsername = username_from_jwt request.cookies['token']
        newUsername = params['username']
        password = params['password']
        secret = params['secret']
        fio = params['fio']

        response = User.change_profile_data(oldUsername, password, secret, fio, newUsername)

        if (response == true)
            status 200
            headers['Set-Cookie'] = "token=#{jwt_from_username newUsername}; path=/; HttpOnly"
            return ""
        end

        status 500
    end

    get '/get-user-data' do
        username = username_from_jwt request.cookies['token']
        user = User.get_user_info(username)
        user.to_json
    end

    get '/users-verified' do
        list = Users_verified.get_list()
        grouped_data = list.group_by { |item| item["username"] }
                  .transform_values { |values| values.map { |value| value["ticketId"] } }
        result = grouped_data.map do |username, ticket_ids|
            {"username" => username, "ticketIds" => ticket_ids}
        end

        result.to_json
    end
end
