#!/usr/bin/ruby
#
# Author:   Erik Aigner
# Website:  chocomoko.com
#

require 'net/http'
require 'socket'
require 'digest/sha1'
require 'cgi'


class Reinvigorate
  
  def initialize(user, pass)
    @user = user
    @password = pass
  end
  
  def pp(h)
    ll = 10
    out = "\n"
    h.each { |k, v|
      l = "#{k} => #{v}"
      ll = [ll, l.length].max
      out << l << "\n"
    }
    puts "-"*ll << out << "-"*ll
  end
  
  def snoop
    @snooping = false
    
    # retrieve snoop endpoint
    http = Net::HTTP.new('report1.reinvigorate.net', '80')
    resp, endpoint = http.get("/snoop?uname=#{@user}")
    
    # define regular expressions
    rx_clr = /client=(\w+)&protocol_version=(\d+)&win_client_version=(.*?)&mac_client_version=(\d+)/
    rx_arsp = /email=(\w+%40\w+.\w+)&auth=(\w+)&member_status=(\w+)&username=(\w+)/
    rx_manifest = /page_option(\d+)=(\w+)&website_title(\d+)=(\w+)&group_title(\d+)=([\w%]+)&hash(\d+)=([\w-]+)&url(\d+)=([\w%\.]+)/ # &length=(\d+)/
    rx_snoop = /stop=(\w+)\r\nsnoop=(\w+)/
    rx_data = /title=(.*)&am=(.*)&ses=(.*)&rnd=(.*)&ct=(.*)&wkey=(.*)&ip=(.*)&bwr=(.*)&lt=(.*)&std=(.*)&bwrv=(.*)&nt=(.*)&os=(.*)&pp=(.*)&proxtm=(.*)&vt=(.*)&url=(.*)&ses_index=(.*)&cook=(.*)&osv=(.*)/
    
    if endpoint and /\w+\.\w+\.\w+/.match(endpoint)
      puts "response-body: #{endpoint}"
      
      # contact snoop endpoint at port 8081
      socket = TCPSocket.open(endpoint, '8081')
      socket.write("client\r\n")
      
      while true
        partial_data = socket.recv(1012)
        
        if @snooping
          m = rx_data.match(partial_data)
          if m and m.size == 21
            ping = {
              :title => m[1],
              :am => m[2],
              :ses => m[3],
              :rnd => m[4],
              :ct => m[5],
              :wkey => m[6],
              :ip => m[7],
              :bwr => CGI::unescape(m[8]),
              :lt => CGI::unescape(m[9]),
              :std => m[10],
              :bwrv => m[11],
              :nt => m[12],
              :os => m[13],
              :pp => CGI::unescape(m[14]),
              :proxtm => m[15],
              :vt => m[16],
              :url => CGI::unescape(m[17]),
              :ses_index => m[18],
              :cook => m[19],
              :osv => CGI::unescape(m[20])
            }
            
            self.pp(ping)
            
          else
            puts "could not parse data:\n#{partial_data}"
          end          
        end
        
        # check for message matches
        clr = rx_clr.match(partial_data)
        arsp = rx_arsp.match(partial_data)
        manifest = rx_manifest.match(partial_data)
        snoop = rx_snoop.match(partial_data)
        
        if partial_data.length == 0
          break
        elsif clr and /ok/.match(clr[0])
          puts ":: received ok => responding with password sha-1"
          
          # send auth request
          pass_sha1 = Digest::SHA1.hexdigest(@password)
          socket.write("password=#{pass_sha1}&username=#{@user}\r\n")
          
        elsif arsp and /ok/.match(arsp[2])
          puts ":: received authentication ok => fetching manifest"
          
          # send manifest request
          socket.write("manifest\r\n")
          
        elsif manifest
          sites = []
          partial_data.gsub(rx_manifest) { |m|
            s = rx_manifest.match(m.to_s)
            sites << {
              :page_option => s[2],
              :website_title => s[4],
              :group_title => CGI::unescape(s[6]),
              :hash => s[8],
              :url => CGI::unescape(s[10])
            }
          }
          
          puts ":: received registered sites"
          sites.each { |site|
            self.pp(site)
          }
          
          # snoop on the first hash by default
          hash = sites[0][:hash]
          puts ":: snooping on #{hash}"
          
          socket.write("snoop=#{hash}\r\n")
          
        elsif snoop and /ok/.match(snoop[2])
          puts ":: snooping!"
          @snooping = true
        end
      end
      socket.close

    else
      raise "could not reach snoop endpoint"
    end
  end
end

Reinvigorate.new('username', 'pass').snoop