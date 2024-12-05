class CustomParamMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    req = Rack::Request.new(env)
    controller = extract_controller_name(req.path_info)
    
    if req.env["REQUEST_METHOD"] != "POST"
      if req.params['controller'].nil?
        req.update_param('controller', [controller])
      end
    end
    
    @app.call(req.env)
  end

  private

  def extract_controller_name(path)
    path.split('/')[2] || nil
  end
end
