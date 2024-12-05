require 'rack/response'

class DinoApp < Sinatra::Base
  $hmac_secret = "my$ecretK3y"
  $algorithm = 'HS256'
  $who = 'controller'
  
  def set_default( defaults={} )
    warn "Entering set_defaults"
    h = defaults.each_with_object({}) do |(k,v),h|
      h[k.to_s] = defaults[k]
    end
    params.merge!( h.merge params )
  end

  def self.stat_get( params=nil, r = {} )
    if (t = params['controller']).nil?
      nil
    end

    if t.is_a?(String)
      t = [t]
    end

    t.each do |tt|
      begin
        r[tt] = tt.classify.constantize.find_by(id: params['id'])
      rescue NameError
      end
    end
    r
  end

  def username_from_jwt(token)
    if token.empty?
      return nil
    end

    begin
      JWT.decode(token, $hmac_secret, true, {algorithm: $algorithm})[0]['username']
    rescue JWT::ExpiredSignature
      nil
    end
  end

  def jwt_from_username(username)
    if username.empty?
      nil
    end

    JWT.encode({username: username, exp: 15.minutes.from_now.to_i}, $hmac_secret, $algorithm)
  end
end
