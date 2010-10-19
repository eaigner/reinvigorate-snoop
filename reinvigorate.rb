#!/usr/bin/ruby
#
# Author:   Erik Aigner
# Website:  chocomoko.com
#

require 'rubygems'
require 'net/http'
require 'socket'
require 'digest/sha1'
require 'cgi'

# gems
require 'highline/import'
require 'term/ansicolor'

include Term::ANSIColor


class Reinvigorate
  
  def initialize(user, pass)
    @user = user
    @password = pass
  end
  
  def snoop
    @snooping = false
    
    # retrieve snoop endpoint
    http = Net::HTTP.new('report1.reinvigorate.net', '80')
    resp, endpoint = http.get("/snoop?uname=#{@user}")
    
    # define regular expressions
    rx_clr = /client=(.*)&protocol_version=(.*)&win_client_version=(.*)&mac_client_version=(.*)/
    rx_arsp = /email=(.*)&auth=(.*)&member_status=(.*)&username=(.*)/
    rx_manifest = /page_option(.*)=(.*)&website_title(.*)=(.*)&group_title(.*)=(.*)&hash(.*)=(.*)&url(.*)=(.*)&?/ # &length=(\d+)/
    rx_snoop = /stop=(.*)\r\nsnoop=(.*)/
    
    if endpoint and /\w+\.\w+\.\w+/.match(endpoint)
      print ":: endpoint => #{endpoint}\n".yellow
      
      # contact snoop endpoint at port 8081
      socket = TCPSocket.open(endpoint, '8081')
      socket.write("client\r\n")
      
      while true
        partial_data = socket.recv(1012)
        # puts partial_data
        
        if @snooping
          ping = CGI::parse(partial_data)
          self.pp(:hash => ping, :lbottom => false, :print_empty => false)
        end
        
        # check for message matches
        clr = rx_clr.match(partial_data)
        arsp = rx_arsp.match(partial_data)
        manifest = rx_manifest.match(partial_data)
        snoop = rx_snoop.match(partial_data)
        
        if partial_data.length == 0
          break
        elsif clr and /ok/.match(clr[0])
          print ":: received ok => responding with password sha-1\n".green
          
          # send auth request
          pass_sha1 = Digest::SHA1.hexdigest(@password)
          socket.write("password=#{pass_sha1}&username=#{@user}\r\n")
          
        elsif arsp and /ok/.match(arsp[2])
          print ":: received authentication ok => fetching manifest\n".green
          
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
          
          print ":: received registered sites\n".green
          sites.each { |site|
            self.pp(:hash => site)
          }
          
          # snoop on the first hash by default
          hash = sites[0][:hash]
          print ":: snooping on #{hash}\n".green
          
          socket.write("snoop=#{hash}\r\n")
          
        elsif snoop and /ok/.match(snoop[2])
          print ":: snooping!\n".green
          @snooping = true
        elsif /auth=bad/.match(partial_data)
          puts ":: bad auth!\n".red.bold
          break;
        end
      end
      socket.close

    else
      raise "could not reach snoop endpoint"
    end
  end
  
  def pp(params)
    ll = 10
    out = ""
    params[:hash].each { |k, v|
      if (params[:print_empty].nil? or params[:print_empty] == true) or (params[:print_empty] == false and v.to_s.length > 0)
        l = "#{k.to_s.chomp} => #{v.to_s.chomp}"
        ll = [ll, l.length].max
        out << l << "\n"
      end
    }
    if params[:ltop].nil? or params[:ltop] == true
      puts "-"*ll
    end
    puts out
    if params[:lbottom].nil? or params[:lbottom] == true
      puts "-"*ll
    end
  end
  
end


# check script arguments
if ARGV[0]
  pass = ask("Enter password:") { |q|
    q.echo = "*"
  }
  
  Reinvigorate.new(ARGV[0], pass).snoop
else
  print "No username provided!\n".red.bold
end
