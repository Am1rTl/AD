require 'open-uri'

class Dino < ActiveRecord::Base
    def self.get( params=nil )
        return DinoApp::stat_get params
    end

    def self.get_all
      Dino.where(allowed: true)
    end

    def self.create_multiple_dino( content )
      content.each do |dino|
        image = dino[:image]
        if image.empty?
          image = "https://i.ytimg.com/vi/Z3p7XK_wjY8/hqdefault.jpg"
        end

        image_name = Digest::SHA2.hexdigest image

        URI.open(image) do |img|
          File.open("./app/public/img/#{image_name}", "wb") do |file|
            file.write(img.read)
          end
        end

        Dino.create(name: dino[:name], description: dino[:description], image: image_name, allowed: dino [:allowed])
      end
    end
end
