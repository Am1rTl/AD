require 'rack/query_parser'
require 'rack/bad_request'
require 'rack/multipart'
require 'uri'
require 'json'

module Rack
  class QueryParser
    def parse_nested_query(qs, separator = nil)
      params = make_params

      unless qs.nil? || qs.empty?
        
        separators = /[;&]/n
        (qs || '').split(separators).each do |p|
          k, v = p.split('=', 2).map! { |s| unescape(s) }

          _normalize_params(params, k, v, 0)
        end
      end

      return params.to_h
    rescue ArgumentError => e
      raise InvalidParameterError, e.message, e.backtrace
    end
  end

  
  class Request
    module Helpers
      def POST
        if error = get_header(RACK_REQUEST_FORM_ERROR)
          raise error.class, error.message, cause: error.cause
        end

        begin
          rack_input = get_header(RACK_INPUT)
          
          if form_hash = get_header(RACK_REQUEST_FORM_HASH)
            form_input = get_header(RACK_REQUEST_FORM_INPUT)
            
            if form_input.equal?(rack_input)
              return form_hash
            elsif form_input
              warn "input stream used for POST parsing different from current input stream. Starting in Rack 3.2, Rack will use the cached POST value instead of parsing the current input stream.", uplevel: 1
            end
          end

          if rack_input.nil?
            set_header RACK_REQUEST_FORM_INPUT, nil
            set_header(RACK_REQUEST_FORM_HASH, {})
          elsif media_type == "application/json"
            form_vars = get_header(RACK_INPUT).read
            set_header RACK_REQUEST_FORM_HASH, JSON.parse(form_vars)

            get_header(RACK_REQUEST_FORM_HASH)
          elsif form_data? || parseable_data?
            form_vars = get_header(RACK_INPUT).read

            form_vars.slice!(-1) if form_vars.end_with?("\0")

            set_header RACK_REQUEST_FORM_VARS, form_vars
            set_header RACK_REQUEST_FORM_HASH, parse_query(form_vars, '&')
          else
            set_header RACK_REQUEST_FORM_INPUT, get_header(RACK_INPUT)
            set_header(RACK_REQUEST_FORM_HASH, {})
          end
        rescue => error
          set_header(RACK_REQUEST_FORM_ERROR, error)
          raise
        end
      end
    end
  end
end
