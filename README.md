#!/usr/bin/env bash
# deploy.sh — StreamPulse installer/deployer with DEMO mode
# Usage: ./deploy.sh {demo|install|deploy}
set -eEuo pipefail

LOG(){ echo "[$(date +'%F %T')] $*"; }

# ─── 1) كشف الوضعية (mode) ───
MODE="${1:-}"
DEMO=false
if [ "$MODE" = "demo" ]; then
  DEMO=true
  LOG "⚡ Running in DEMO mode — skipping privileged operations"
  SUDO=""
  PM=""
else
  # اكتشاف صلاحيات root أو sudo
  if [ "$(id -u)" -eq 0 ]; then
    SUDO=""; LOG "Running as root"
  elif command -v sudo &>/dev/null; then
    SUDO="sudo"; LOG "Using sudo for privileged ops"
  else
    SUDO=""; LOG "⚠️ No sudo/root — skipping system installs"
  fi
  # اكتشاف مدير الحزم
  if command -v apt-get &>/dev/null; then
    PM="apt-get"
  elif command -v apt &>/dev/null; then
    PM="apt"
  else
    PM=""
  fi
fi

# ─── 2) المتغيرات الأساسية ───
APP_DIR="$HOME/streampulse"
REPO="https://github.com/your-github-username/streampulse.git"
BRANCH="main"
NODE_VERSION="16"
DOMAIN="streampulse.com"
LOGFILE="$HOME/streampulse_install.log"
BACKUP_DIR="$HOME/streampulse_backups"

# بيانات الدفع
PAYMENT_NUMBER="01033628570"
PAYMENT_PROVIDERS="VodafoneCash,OrangeCash,EtisalatCash"

# MongoDB site verification
MONGODB_VERIFICATION_KEY="pXsAwVcATOMYBLDsf1F8rpKQEtA4MyJJ"

# OIDC (Auth0)
OIDC_ISSUER="https://streampulse-oid0.cauth0.com"
OIDC_CLIENT_ID="YOUR_AUTH0_CLIENT_ID"
OIDC_CLIENT_SECRET="YOUR_AUTH0_CLIENT_SECRET"
OIDC_REDIRECT_URI="https://$DOMAIN/api/auth/oidc/callback"

# GCP Billing (install/deploy only)
GCP_PROJECT_ID="your-gcp-project-id"
GCP_BILLING_ACCOUNT_ID="000000-AAAAAA-BBBBBB"
BILLING_USER_EMAIL="Mahmoudnasser9999@gmail.com"
export GOOGLE_APPLICATION_CREDENTIALS="$HOME/streampulse/gcp-sa-key.json"

# سجلات ونسخ احتياطيّة
mkdir -p "$(dirname "$LOGFILE")" "$BACKUP_DIR"
touch "$LOGFILE"
exec &> >(tee -a "$LOGFILE")

################################################################################
# دوال العمليات
################################################################################

install_system(){
  if $DEMO || [ -z "$PM" ] || { [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ]; }; then
    LOG "Skipping system packages installation"
    return
  fi
  LOG "Installing system packages via $PM"
  $SUDO $PM update && $SUDO $PM upgrade -y
  $SUDO $PM install -y git curl build-essential ufw nginx \
    certbot python3-certbot-nginx ffmpeg mongodb redis-server fail2ban
  curl -fsSL https://deb.nodesource.com/setup_"$NODE_VERSION".x | $SUDO bash -
  $SUDO $PM install -y nodejs
  $SUDO npm install -g pm2 npm-check-updates
}

prepare_host(){
  if $DEMO || { [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ]; }; then
    LOG "Configuring OS user & UFW"
    id streampulse &>/dev/null || $SUDO useradd -m -s /bin/bash streampulse
    $SUDO ufw default deny incoming
    $SUDO ufw default allow outgoing
    $SUDO ufw allow ssh http https
    $SUDO ufw --force enable
    $SUDO systemctl enable --now mongodb redis-server fail2ban || true
  else
    LOG "Skipping host preparation"
  fi
}

clone_repo(){
  LOG "Cloning/updating repository"
  if [ -d "$APP_DIR" ]; then
    git -C "$APP_DIR" fetch
    git -C "$APP_DIR" checkout "$BRANCH"
    git -C "$APP_DIR" pull
  else
    git clone -b "$BRANCH" "$REPO" "$APP_DIR"
  fi
  $SUDO chown -R streampulse:streampulse "$APP_DIR" || true
}

setup_backend(){
  LOG "Setting up backend"
  cd "$APP_DIR/backend"
  cat > .env <<EOF
PORT=5000
DB_URI=mongodb://localhost:27017/streampulse
DOMAIN=$DOMAIN
JWT_SECRET=demo_jwt
COOKIE_SECRET=demo_cookie
OIDC_ISSUER=$OIDC_ISSUER
OIDC_CLIENT_ID=$OIDC_CLIENT_ID
OIDC_CLIENT_SECRET=$OIDC_CLIENT_SECRET
OIDC_REDIRECT_URI=$OIDC_REDIRECT_URI
SENTRY_DSN=
EOF
  npm ci
  cd - >/dev/null
}

generate_helpers(){
  LOG "Generating helper files"
  mkdir -p "$APP_DIR/backend/middleware" "$APP_DIR/backend/utils"
  # validation.js
  cat > "$APP_DIR/backend/middleware/validation.js" <<'EOF'
const { validationResult } = require('express-validator');
module.exports=(req,res,next)=>{
  const errors=validationResult(req);
  if(!errors.isEmpty()) return res.status(400).json({errors:errors.array()});
  next();
};
EOF
  # csrf.js
  cat > "$APP_DIR/backend/utils/csrf.js" <<'EOF'
const csrf=require('csurf')({cookie:true});
module.exports=csrf;
EOF
  # passport.js (Google + Facebook)
  cat > "$APP_DIR/backend/utils/passport.js" <<'EOF'
const passport=require('passport');
const GoogleStrategy=require('passport-google-oauth20').Strategy;
const FacebookStrategy=require('passport-facebook').Strategy;
const User=require('../models/User');
passport.use(new GoogleStrategy({
  clientID:process.env.GOOGLE_CLIENT_ID,
  clientSecret:process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:'/api/auth/google/callback'
},async(token,refresh,profile,done)=>{
  let u=await User.findOne({oauthId:profile.id});
  if(!u) u=await User.create({oauthId:profile.id,username:profile.displayName,email:profile.emails[0].value});
  done(null,u);
}));
passport.use(new FacebookStrategy({
  clientID:process.env.FACEBOOK_APP_ID,
  clientSecret:process.env.FACEBOOK_APP_SECRET,
  callbackURL:'/api/auth/facebook/callback'
},async(token,refresh,profile,done)=>{
  let u=await User.findOne({oauthId:profile.id});
  if(!u) u=await User.create({oauthId:profile.id,username:profile.displayName,email:profile._json.email});
  done(null,u);
}));
passport.serializeUser((u,done)=>done(null,u.id));
passport.deserializeUser((id,done)=>User.findById(id).then(u=>done(null,u)).catch(e=>done(e)));
module.exports=passport;
EOF
  # mailer.js
  cat > "$APP_DIR/backend/utils/mailer.js" <<'EOF'
const nodemailer=require('nodemailer');
const t=nodemailer.createTransport({
  host:process.env.MAIL_HOST,port:process.env.MAIL_PORT,
  secure:process.env.MAIL_SECURE==='true',
  auth:{user:process.env.MAIL_USER,pass:process.env.MAIL_PASS}
});
module.exports={sendMail:(to,sub,html)=>t.sendMail({from:process.env.MAIL_FROM,to,subject:sub,html})};
EOF
}

inject_security(){
  LOG "Injecting security middleware"
  S="$APP_DIR/backend/server.js"
  sed -i "1i require('dotenv').config();" "$S"
  cat <<'EOF' >> "$S"

const cookieParser=require('cookie-parser');
const csrf=require('./utils/csrf');
const rateLimit=require('express-rate-limit');
const helmet=require('helmet');
const cors=require('cors');
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use(csrf);
app.use(rateLimit({windowMs:900000,max:100}));
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:[\"'self'\"],scriptSrc:[\"'self'\"],styleSrc:[\"'self'\"],imgSrc:[\"'self'\",\"data:\"]}}}));
app.use(cors({origin:[\`https://${DOMAIN}\`],credentials:true}));
app.use((req,res,next)=>{res.cookie('XSRF-TOKEN',req.csrfToken(),{httpOnly:true,secure:true,sameSite:'strict'});next();});
EOF
}

add_video_index(){
  LOG "Adding text index to Video model"
  sed -i "/new mongoose.Schema/a\\  videoSchema.index({title:'text',description:'text'});" "$APP_DIR/backend/models/Video.js"
}

generate_oauth_routes(){
  LOG "Generating OAuth routes"
  cat > "$APP_DIR/backend/routes/passportRoutes.js" <<'EOF'
const r=require('express').Router(),p=require('passport');
r.get('/google',p.authenticate('google',{scope:['profile','email']}));
r.get('/google/callback',p.authenticate('google',{session:false,failureRedirect:'/login'}),(req,res)=>res.redirect('/'));
r.get('/facebook',p.authenticate('facebook',{scope:['email']}));
r.get('/facebook/callback',p.authenticate('facebook',{session:false,failureRedirect:'/login'}),(req,res)=>res.redirect('/'));
module.exports=r;
EOF
  sed -i "/app.use('\/api\/auth'/a\  app.use('/api/auth',require('./routes/passportRoutes'));" "$APP_DIR/backend/server.js"
}

generate_oidc_auth_support(){
  LOG "Generating OIDC (Auth0) routes"
  mkdir -p "$APP_DIR/backend/routes"
  cat > "$APP_DIR/backend/routes/oidcRoutes.js" <<'EOF'
const express=require('express');
const {Issuer}=require('openid-client');
const User=require('../models/User');
(async()=>{
  const issuer=await Issuer.discover(process.env.OIDC_ISSUER);
  const client=new issuer.Client({
    client_id:process.env.OIDC_CLIENT_ID,
    client_secret:process.env.OIDC_CLIENT_SECRET,
    redirect_uris:[process.env.OIDC_REDIRECT_URI],
    response_types:['code']
  });
  const router=express.Router();
  router.get('/login',(req,res)=>{
    const url=client.authorizationUrl({scope:'openid profile email',response_mode:'query'});
    res.redirect(url);
  });
  router.get('/callback',async(req,res)=>{
    const params=client.callbackParams(req);
    const tokenSet=await client.callback(process.env.OIDC_REDIRECT_URI,params);
    const userInfo=await client.userinfo(tokenSet.access_token);
    let u=await User.findOne({oauthId:userInfo.sub});
    if(!u) u=await User.create({oauthId:userInfo.sub,username:userInfo.name||userInfo.email,email:userInfo.email});
    res.redirect('/');
  });
  module.exports=router;
})();
EOF
  sed -i "/app.use('\/api\/auth'/a\  app.use('/api/auth/oidc',require('./routes/oidcRoutes'));" "$APP_DIR/backend/server.js"
}

add_health(){
  LOG "Adding /health endpoint"
  sed -i "/app.use('\/api\/tasks'/a\  app.get('/health',(req,res)=>res.sendStatus(200));" "$APP_DIR/backend/server.js"
}

setup_migrations(){
  LOG "Initializing migrate-mongo"
  cd "$APP_DIR/backend"
  [ -f migrate-mongo-config.js ] || npx migrate-mongo init
  cd - >/dev/null
}

setup_monitoring(){
  LOG "Setting up metrics & Swagger"
  S="$APP_DIR/backend/server.js"
  sed -i "1i const promBundle=require('express-prom-bundle');const swaggerUi=require('swagger-ui-express');const jsdoc=require('swagger-jsdoc');" "$S"
  cat <<'EOF' >> "$S"

app.use(promBundle({includeMethod:true,includePath:true}));
const specs=jsdoc({definition:{openapi:'3.0.0',info:{title:'StreamPulse API',version:'1.0.0'}},apis:['./routes/*.js']});
app.use('/docs',swaggerUi.serve,swaggerUi.setup(specs));
EOF
}

generate_video_fetcher(){
  LOG "Generating videoFetcher util"
  cat > "$APP_DIR/backend/utils/videoFetcher.js" <<'EOF'
const TikTokScraper=require('tiktok-scraper');
async function getExampleVideos(c=5){
  try{
    const p=await TikTokScraper.trend('com',{number:c});
    return p.collector.filter(v=>v.videoMeta.duration===60).map(v=>\`https://www.tiktok.com/@\${v.authorMeta.name}/video/\${v.id}\`);
  }catch{ return []; }
}
module.exports={getExampleVideos};
EOF
}

setup_tasks(){
  LOG "Seeding tasks"
  cat > "$APP_DIR/backend/seedPlatform.js" <<'EOF'
(async()=>{
  const Task=require('./models/Task');
  await Task.deleteMany({});
  await Task.create([
    {title:"Demo task A",description:"Desc A",prize:"0 EGP",type:"daily"},
    {title:"Demo task B",description:"Desc B",prize:"0 EGP",type:"subscription",package:"Demo"}
  ]);
  console.log("Demo tasks seeded");
  process.exit(0);
})();
EOF
}

setup_frontend(){
  LOG "Building frontend"
  cd "$APP_DIR/frontend"
  cat > .env <<EOF
REACT_APP_API_URL=/api
REACT_APP_PAYMENT_NUMBER=$PAYMENT_NUMBER
REACT_APP_PAYMENT_PROVIDERS=$PAYMENT_PROVIDERS
EOF
  npm ci
  npm run build
  cd - >/dev/null
}

generate_frontend_pages(){
  LOG "Generating React pages"
  # (يمكن إضافة صفحات وهمية هنا حسب الحاجة)
  :
}

generate_mongodb_verification_file(){
  LOG "Generating MongoDB site verification file"
  mkdir -p "$APP_DIR/frontend/public"
  echo "<!-- mongodb-site-verification=$MONGODB_VERIFICATION_KEY -->" \
    > "$APP_DIR/frontend/public/mongodb-site-verification.html"
}

generate_docker_compose(){
  LOG "Generating demo docker-compose.yml"
  cat > "$APP_DIR/docker-compose.yml" <<'EOF'
version: '3.8'
services:
  mongo:
    image: mongo:5
    volumes:
      - ./backend/data:/data/db
  app:
    build: ./backend
    ports:
      - "5000:5000"
    depends_on:
      - mongo
EOF
}

run_demo(){
  LOG "Starting DEMO platform"
  install_system
  clone_repo
  setup_backend
  generate_helpers
  inject_security
  add_video_index
  generate_oauth_routes
  generate_oidc_auth_support
  add_health
  setup_migrations
  setup_monitoring
  generate_video_fetcher
  setup_tasks
  setup_frontend
  generate_frontend_pages
  generate_mongodb_verification_file
  generate_docker_compose
  LOG "Launching with Docker Compose"
  cd "$APP_DIR" && docker-compose up --build -d
  LOG "✅ DEMO running at http://localhost:5000"
}

run_install(){
  LOG "Starting REAL installation"
  install_system
  prepare_host
  clone_repo
  setup_backend
  generate_helpers
  inject_security
  add_video_index
  generate_oauth_routes
  generate_oidc_auth_support
  add_health
  setup_migrations
  setup_monitoring
  generate_video_fetcher
  setup_tasks
  setup_frontend
  generate_frontend_pages
  generate_mongodb_verification_file
  configure_gcp_billing
  setup_nginx_ssl
  start_pm2
  LOG "✅ Installation complete — StreamPulse is live!"
}

run_deploy(){
  LOG "Redeploying updates"
  clone_repo
  setup_backend
  setup_frontend
  generate_mongodb_verification_file
  configure_gcp_billing
  setup_nginx_ssl
  pm2 restart streampulse-backend streampulse-frontend
  LOG "✅ Redeploy complete!"
}

case "$MODE" in
  demo)   run_demo   ;;
  install)run_install;;
  deploy) run_deploy ;;
  *) echo "Usage: $0 {demo|install|deploy}" >&2; exit 1 ;;
esac
