require "bcrypt"
require "inifile"
require "io/console"
require "net/smtp"
require "securerandom"
require "sequel"
require "sinatra"
require "sqlite3"
require "uri"

DB = Sequel.sqlite("users.db")

DB.create_table? :user do
  primary_key :id
  String  :nickname, null: false
  String  :identity_hash,  null: false
  TrueClass :confirmed,    default: false
  String  :confirmation_token
  DateTime :created_at
end

USER = DB[:user]

if ARGV.include?("-i") || ARGV.include?("--interactive")
  print "Your domain:"
  $domain = STDIN.gets.chomp
  print "SMTP host:"
  $smtp_server = STDIN.gets.chomp
  print "SMTP port:"
  $smtp_port = STDIN.gets.chomp
  print "SMTP user:"
  $smtp_user = STDIN.gets.chomp
  print "SMTP password:"
  $smtp_pass = STDIN.noecho(&:gets).chomp
  puts
else
  config = IniFile.load("config.ini")
  if config.nil? || !config.has_section?("smtp")
    abort "Error: please create a config.ini file with SMTP settings or use interactive mode (-i)."
  end
  $domain       = config["smtp"]["domain"]
  $smtp_server  = config["smtp"]["server"]
  $smtp_port    = config["smtp"]["port"].to_i
  $smtp_user    = config["smtp"]["user"]
  $smtp_pass    = config["smtp"]["pass"]
  if [$domain, $smtp_server, $smtp_port, $smtp_user].any?(&:nil?)
    abort "Error: please create a config.ini file with SMTP settings or use interactive mode (-i)."
  end

  if $smtp_pass.nil? || $smtp_pass.empty?
    print "SMTP password:"
    $smtp_pass = STDIN.noecho(&:gets).chomp
    puts
  end
end

get "/" do
  <<-HTML
  <html>
    <head>
      <title>Signing up</title>
    </head>
    <body>
      <h1>Create an account</h1>
      <form method="POST" action="/signup">
        <label>nickname:</label><br>
        <input type="text" name="nickname" required /><br><br>

        <label>Email:</label><br>
        <input type="email" name="email" required /><br><br>

        <label>Password:</label><br>
        <input type="password" name="password" required /><br><br>

        <button type="submit">Sign up</button>
      </form>
    </body>
  </html>
  HTML
end

post "/signup" do
  nickname = params["nickname"]
  email    = params["email"]
  password = params["password"]

  USER.each do |user|
    stored_nickname = user[:nickname]

    if nickname == stored_nickname
      halt 400, "❌ Error: nickname already taken"
    end
  end

  identity_hash = BCrypt::Password.create(email + password, cost: 12)

  puts email
  puts password
  puts identity_hash
  
  confirmation_token = SecureRandom.hex(20)

  USER.insert(
    nickname: nickname,
    identity_hash: identity_hash,
    confirmation_token: confirmation_token,
    created_at: Time.now
  )

  send_confirmation_email(email, confirmation_token)

  "🎉 Account created for #{nickname} (#{email}) — a confirmation email has been sent."
end


helpers do
  def send_confirmation_email(recipient_email, token)
    from    = "#{$smtp_user}@#{$domain}"
    subject = "Confirm your account"

    confirm_url = URI::HTTP.build(host: request.host, port: request.port, path: "/confirm", query: "token=#{token}")
    body    = <<~EOM
      Hello,

      Thank you for signing up. To confirm your account, please click the following link:
      #{confirm_url}

      See you soon,
      The Team
    EOM

    puts "Sending confirmation email to #{recipient_email} via #{$smtp_server}:#{$smtp_port} as #{$smtp_user}@#{$domain}"

    Net::SMTP.start($smtp_server, $smtp_port, $domain, "#{$smtp_user}@#{$domain}", $smtp_pass, :login) do |smtp|
      smtp.enable_ssl
      message = <<~MSG
        From: #{from}
        To: #{recipient_email}
        Subject: #{subject}

        #{body}
      MSG
      smtp.send_message message, from, recipient_email
    end
  rescue => e
    warn "Error sending confirmation email: #{e.message}"
  end
end

get "/confirm" do
  token = params["token"]
  user  = USER.where(confirmation_token: token).first
  if user
    USER.where(id: user[:id]).update(confirmed: true, confirmation_token: nil)
    "✅ Your account has been confirmed!"
  else
    halt 400, "Invalid confirmation token"
  end
end
