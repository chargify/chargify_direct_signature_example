require 'sinatra'
require 'openssl'
require 'addressable/uri'
require 'pp'

HMAC_SHA1_DIGEST = OpenSSL::Digest::Digest.new('sha1')

get '/' do
  erb :index
end

post '/compute' do
  signature = hexdigest(params[:api_id], params[:timestamp], params[:nonce], params[:data], params[:api_secret])
  uri = Addressable::URI.new
  uri.query_values = {
    :api_id => params[:api_id],
    :timestamp => params[:timestamp],
    :nonce => params[:nonce],
    :data => params[:data],
    :api_secret => params[:api_secret],
    :signature => signature
  }
  uri.path = "/"
  
  redirect uri.to_s
end

post '/verify' do
  @expected_signature = hexdigest(params[:secure][:api_id], params[:secure][:timestamp], params[:secure][:nonce], params[:secure][:data], params[:api_secret])
  @actual_signature = params[:secure][:signature]
  erb :verify
end

def hexdigest(api_id, timestamp, nonce, data, secret)
  message = "#{api_id}#{timestamp}#{nonce}#{data}"
  OpenSSL::HMAC.hexdigest(HMAC_SHA1_DIGEST, secret.to_s, message)
end

helpers do
  include Rack::Utils
  alias_method :h, :escape_html
end
