package main 

import (
  "github.com/gorilla/websocket"
  "net/http"
  "sync"
  "fmt"
  "database/sql"
  "os"
  "html/template"
  "time"
  "crypto/aes"
  _"github.com/go-sql-driver/mysql"
)

var mu sync.RWMutex
var upgrader = websocket.Upgrader{ReadBufferSize: 1024,
                                  WriteBufferSize: 1024,
                                  CheckOrigin: func(r *http.Request) bool { return true }}
const secret_key string = "N1PCdw3M2B1TfJhoaY2mL736p2vCUc47"
type Clients struct {
  clients map[string]map[*websocket.Conn]bool
  db *sql.DB
}
var templates = template.Must(template.ParseFiles("templates/chat.html", "templates/chat_page.html", "templates/create_chat_room.html"))
const port = "8080"
var banned_usernames = [6]string{"Root", "ROOT", "root", "Admin", "ADMIN", "admin"}
var only_usernames = [0]string{}
var only_usrs = false
var ref_ltr = [52]uint8{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}
var ref_nb = [10]uint8{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
var banned_char_url = [22]uint8{'_', ' ', '/', '?', '$', 
                           '&', '@', '#', '.', ',', '\\', '|', 
                           '{', '}', '(', ')', '^', '<', '>', '%', ':'}
var ref_spechr = [24]uint8{'!', '.', ':', ';', '\\', '-', '%', '*', ',', '_', '/', '<', '>', '=', '[', ']', '\'', '{', '}', '[', ']', '(', ')', '"'}
var ref_temp_password = [11]uint8{'-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
const server_ip = "127.0.0.1"

func Int32ToString(x *int32) string {
  const base int32 = 10
  var remainder int32
  rtn_str := ""
  for *x > 0 {
    remainder = *x % base
    rtn_str = string(remainder + 48) + rtn_str
    *x -= remainder
    *x /= 10
  }
  return rtn_str
}

func Int64ToString(x *int64) string {
  const base int64 = 10
  var remainder int64
  rtn_str := ""
  for *x > 0 {
    remainder = *x % base
    rtn_str = string(remainder + 48) + rtn_str
    *x -= remainder
    *x /= 10
  }
  return rtn_str
}

func CreateRoomPassword(given_password *string) (string, error) {
 
  aes, err := aes.NewCipher([]byte(secret_key))
  if err != nil {
    return "", err
  }

  ciphered_password := make([]byte, 16)
  aes.Encrypt(ciphered_password, []byte(*given_password))

  var cur_rune int32
  p_rotated := ""
  var cur_str string

  for i := 0; i < 16; i++ {
    cur_rune = int32(ciphered_password[i])
    cur_str = Int32ToString(&cur_rune) + "-"
    p_rotated += cur_str
  }

  return p_rotated, nil
}

func EvaluateConnectionPassword(given_password *string, username *string, db *sql.DB) bool {
  var real_password string
  username_query := db.QueryRow("SELECT password FROM credentials WHERE BINARY username = ?;", username)
  err := username_query.Scan(&real_password)
  if err != nil {
    fmt.Println(err)
    return false
  }
  if real_password != *given_password {
    return false
  }
  return true
}

func EvaluatePassword(given_password *string, username *string, db *sql.DB) bool {
  var real_password string
  username_query := db.QueryRow("SELECT temp_password FROM credentials WHERE username = ?;", username)
  err := username_query.Scan(&real_password)
  if err != nil {
    return false
  }
  if real_password != *given_password {
    return false
  }
  return true
}

func URLToCredentials(url string) (string, string, bool) {
  rtn_str := ""
  rtn_str2 := ""
  var i int = len(url) - 1
  var i3 int
  n_ref := i
  var cur_bool bool
  for url[i] != '_' {
    cur_bool = false
    for i3 = 0; i3 < 11; i3++ {
      if url[i] == ref_temp_password[i3] {
        cur_bool = true
        break
      }
    }
    if !cur_bool {
      return "", "", false
    }
    rtn_str += string(url[i])
    i--
  }
  if i == n_ref {
    return "", "", false
  }
  i--
  for url[i] != '_' {
    for i3 = 0; i3 < 3; i3++ {
      if url[i] == banned_char_url[i3] {
        return "", "", false
      }
    }
    rtn_str2 += string(url[i])
    i--
  }
  i = 0
  var n int = len(rtn_str)
  password_rune := []rune(rtn_str)
  var tmp_val rune
  for i < n / 2 {
    tmp_val = password_rune[i]
    password_rune[i] = password_rune[n - 1 - i]
    password_rune[n - 1 - i] = tmp_val
    i++
  }
  username_rune := []rune(rtn_str2)
  n = len(rtn_str2)
  i = 0
  for i < n / 2 {
    tmp_val = username_rune[i]
    username_rune[i] = username_rune[n - 1 - i]
    username_rune[n - 1 - i] = tmp_val
    i++
  }
  return string(password_rune), string(username_rune), true
}

func CredentialsToURL(tmp_password string, username *string, db *sql.DB) (string, error) {
  cur_time := time.Now().Unix()
  string_time := Int64ToString(&cur_time)
  string_time = string_time[len(string_time) - 4:]
  tmp_password = tmp_password[:12]
  tmp_password += string_time
  
  aes, err := aes.NewCipher([]byte(secret_key))
  if err != nil {
    return "", err
  }
  
  ciphered_password := make([]byte, 16)
  aes.Encrypt(ciphered_password, []byte(tmp_password))
  
  p_rotated_link := ""
  var cur_str string
  var cur_rune int32
  var rotated_link string
  
  for i := 0; i < 16; i++ {
    cur_rune = int32(ciphered_password[i])
    cur_str = Int32ToString(&cur_rune) + "-"
    p_rotated_link += cur_str
  }
  
  _, err = db.Exec("UPDATE credentials SET temp_password=? WHERE username=?;", p_rotated_link, *username)
  rotated_link = "_" + *username + "_" + p_rotated_link

  return rotated_link, nil
}

func ValidateURL(x string) bool {
  var i2 int
  var cur_val uint8
  for i:= 0; i < len(x); i++ {
    cur_val = x[i]
    for i2 = 0; i2 < 22; i2++ {
      if cur_val == banned_char_url[i2] {
        return false
      }
    }
  }
  return true
}

func GoodUsername(given_username string) bool {
  if len(given_username) == 0 {
    return false
  }
  var i2 int
  var cur_val uint8
  fmt.Println("ok")
  for i:= 0; i < len(given_username); i++ {
    cur_val = given_username[i]
    for i2 = 0; i2 < 22; i2++ {
      if cur_val == banned_char_url[i2] {
        return false
      }
    }
  }
  fmt.Println("ok2")
  for _, usr := range banned_usernames {
    if given_username == usr {
      return false
    }
  }
  var is_in = false
  if only_usrs {
    for _, usr := range banned_usernames {
      if given_username == usr {
        is_in = true
        break
      }
    }
    if !is_in {
      return false
    }
  }
  return true 
}

func GoodPassword(given_password string) bool {
  var n int = len(given_password)
  if n != 16 {
    return false
  }
  var i uint = 0
  var i2 uint
  var cur_val uint8
  var agn bool = true
  for agn && i < 16 {
    cur_val = given_password[i]
    i2 = 0
    for i2 < 10 && cur_val != ref_nb[i2] {
      i2++
    }
    if i2 < 10 {
      agn = false
    }
    i++
  }
  if agn {
    return false
  }
  agn = true
  i = 0
  for agn && i < 16 {
    cur_val = given_password[i]
    i2 = 0
    for i2 < 52 && cur_val != ref_ltr[i2] {
      i2++
    }
    if i2 < 52 {
      agn = false
    }
    i++
  }
  i = 0
  if agn {
    return false
  }
  agn = true
  for agn && i < 16 {
    cur_val = given_password[i]
    i2 = 0
    for i2 < 24 && cur_val != ref_spechr[i2] {
      i2++
    }
    if i2 < 24 {
      agn = false
    }
    i++
  }
  if agn {
    return false
  }
  return true
}

func (clients *Clients) HandleWSConnection(w http.ResponseWriter, 
                        r *http.Request) {
  ws, err := upgrader.Upgrade(w, r, nil)
  if err != nil {
    fmt.Println("error connecting")
    fmt.Println(err)
    return
  }
  var msg []byte
  var msg_type int
  cur_url := r.URL.Path
  if len(cur_url) == 4 {
    fmt.Println("not valid url / chatroom")
    return
  }

  password, username, is_valid := URLToCredentials(cur_url)
  if !is_valid {
    w.Write([]byte("<b>Not valid URL</b>"))
    return
  }
  is_valid = EvaluatePassword(&password, &username, clients.db)
  if !is_valid {
    w.Write([]byte("<b>Not alowed to be here</b>"))
    return
  }

  chat_room := ""
  var i int
  for i = 4; i < len(cur_url); i++ {
    if cur_url[i] != '_' {
      chat_room += string(cur_url[i])
    } else {
      break
    }
  }
 
  is_valid = ValidateURL(chat_room)
  if !is_valid {
    fmt.Println("not valid url / chatroom")
    return
  }

  var found_name string
  content := clients.db.QueryRow("SELECT name FROM chat_room WHERE BINARY name=?;", chat_room)
  err = content.Scan(&found_name)
  if err != nil {
    fmt.Println(err)
    w.Write([]byte("<b>This chat room does not exist</b>"))
    return
  }

  mu.Lock()
  if clients.clients[chat_room] == nil { 
    clients.clients[chat_room] = make(map[*websocket.Conn]bool)
  }
  clients.clients[chat_room][ws] = true
  mu.Unlock()
  prefix_msg := username + ": "
  var str_msg string
  msg = []byte("System: " + username + " connected")
  msg_type = 1
  go clients.Broadcast(&msg, &msg_type, &chat_room)
  defer clients.Disconnection(&chat_room, ws, &username)
  for {
    msg_type, msg, err = ws.ReadMessage()
    if err != nil {
      fmt.Println("error reading message: ", err)
      break
    }
    str_msg = prefix_msg + string(msg)
    msg = []byte(str_msg)
    fmt.Println("New message: ", string(msg))
    go clients.Broadcast(&msg, &msg_type, &chat_room)
  }
}

func (clients *Clients) Broadcast(buffr *[]byte, 
                                  msg_type *int,
                                  chat_room *string) {
  mu.RLock()
  var err error
  for cur_ws := range clients.clients[*chat_room] {
    err = cur_ws.WriteMessage(*msg_type, (*buffr))
    if err != nil {
      fmt.Println("error broadcasting message")
      fmt.Println(err)
      return
    }
  }
  mu.RUnlock()
}

func (clients *Clients) Disconnection(chat_room *string, 
                                      ws *websocket.Conn, 
                                      username *string) {
  msg := []byte("System: " + *username + " disconnected")
  msg_type := 1
  go clients.Broadcast(&msg, &msg_type, chat_room)
  fmt.Println("client disconnection")
  mu.Lock()
  delete(clients.clients[*chat_room], ws)
  mu.Unlock()
  ws.Close()
}

func ConnectionHandler(db *sql.DB) http.HandlerFunc {
  return func (w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
      w.Write([]byte("<b>Forbidden Method</b>"))
      return
    }

    username_form := r.FormValue("username")
    password_form := r.FormValue("password")
    
    rtn_bool := EvaluateConnectionPassword(&password_form, 
                                           &username_form, 
                                           db)

    if !rtn_bool {
      w.Write([]byte(`<b>Not valid username or password</b><br><a href="../login">Go Back</a>`))
      return
    } else {
      rotated_link, err := CredentialsToURL(password_form, 
                                        &username_form, 
                                        db) 
      if err != nil {
        fmt.Println(err)
        return
      }
      fmt.Println("logged in")
      http.Redirect(w, r, "/chat_page/" + rotated_link, http.StatusFound)
    }
  }
}

func IndexHandler(w http.ResponseWriter, r *http.Request) {
  data, err := os.ReadFile("templates/index.html")
  if err != nil {
    fmt.Println(err)
    w.Write([]byte("<b>Something went wrong</b>"))
    return
  }
  w.Write(data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("<b>Bad Method</b>"))
    return
  }
  if r.URL.Path != "/login/" {
    w.Write([]byte("<b>404, Not Found</b>"))
    return
  }
  data, err := os.ReadFile("templates/login.html")
  if err != nil {
    fmt.Println(err)
    w.Write([]byte("<b>Something went wrong</b>"))
    return
  }
  w.Write(data)
}

func CreateAccountHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != "GET" {
    w.Write([]byte("<b>Bad Method</b>"))
    return
  }
  if r.URL.Path != "/create_account/" {
    w.Write([]byte("<b>404, Not Found</b>"))
    return
  }
  data, err := os.ReadFile("templates/create_account.html")
  if err != nil {
    fmt.Println(err)
    w.Write([]byte("<b>Something went wrong</b>"))
    return
  }
  w.Write(data)
}

func NewAccountHandler(db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    my_url := r.URL.Path
    if my_url != "/new_account/" {
      w.Write([]byte("<b>Bad url</b>"))
      return
    }
    password := r.FormValue("password")
    username := r.FormValue("username")
    fmt.Println("username: ", username)
    fmt.Println("password: ", password)
    is_valid := GoodPassword(password)
    if !is_valid {
      w.Write([]byte("<b>Password not valid</b>"))
      return
    }
    is_valid = GoodUsername(username)
    if !is_valid {
      w.Write([]byte("<b>Username not valid</b>"))
      return
    }
    var alrd_username string
    content := db.QueryRow("SELECT username FROM credentials WHERE BINARY username=?;",
                      username)
    err := content.Scan(&alrd_username)
    if err == nil {
      fmt.Println(err)
      w.Write([]byte("<b>Username already taken</b>"))
      return
    }
    _, err = db.Exec("INSERT INTO credentials VALUE (?, ?, ' ');",
                     username, password)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    _, err = db.Exec("CREATE TABLE " + username + " (chat_room VARCHAR(35));")
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    http.Redirect(w, r, "/login/", http.StatusFound)
    return
  }
}

type ChatPageStruct struct {
  ChatRooms []string
  NextURL string
}

func ChatPageHandler(db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
      w.Write([]byte("<b>Bad Request Method</b>"))
      return
    }
    my_url := r.URL.Path
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>URL not valid</b>"))
      return
    }
    is_valid = EvaluatePassword(&password, &username, db)
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here</b>"))
      return
    }
    content, err := db.Query("SELECT chat_room FROM " + username + ";")
    if err != nil {
      fmt.Print(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    var chat_rooms []string
    var chat_room string
    for content.Next() {
      err = content.Scan(&chat_room)
      if err != nil {
        fmt.Print(err)
        w.Write([]byte("<b>Something went wrong</b>"))
        return
      }
      chat_rooms = append(chat_rooms, chat_room)
    }
    rotated_link, err := CredentialsToURL(password, &username, db)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    cur_struct := ChatPageStruct{ChatRooms: chat_rooms,
                             NextURL: rotated_link}
    err = templates.ExecuteTemplate(w, "chat_page.html", 
                                            cur_struct)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
  }
}

type ChatStruct struct {
  NextURL string
  ChatRoom string
  ServerIP string
  ServerPort string
}

func ChatHandler(db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    my_url := r.URL.Path
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>Bad URL format</b>"))
      return
    }
    is_valid = EvaluatePassword(&password, &username, db)
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here</b>"))
      return
    }
    i := 6
    chat_room := ""
    for my_url[i] != '_' {
      chat_room += string(my_url[i])
      i++
    }
    rotated_link, err := CredentialsToURL(password, &username, db)
    if err != nil {
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    var alrd_chat_room string
    content := db.QueryRow("SELECT chat_room FROM " + username + " WHERE chat_room=?;", 
                                        chat_room)
    err = content.Scan(&alrd_chat_room)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte(`<b>This chat room doesn't exist or is not available for you</b><br><a href=../chat_page/` + rotated_link + `>Go Back</a>`))
      return
    }
    cur_struct := ChatStruct{NextURL: rotated_link, 
                            ChatRoom: chat_room,
                            ServerIP: server_ip,
                            ServerPort: port}
    err = templates.ExecuteTemplate(w, "chat.html", cur_struct)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
  }
}

type CreateChatRoomStruct struct {
  NextURL string
}

func CreateChatHandler(db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    my_url := r.URL.Path
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>URL not valid</b>"))
      return
    }
    is_valid = EvaluatePassword(&password, &username, db)
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here</b>"))
      return
    }
    rotated_link, err := CredentialsToURL(password, &username, db)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    cur_struct := CreateChatRoomStruct{NextURL: rotated_link}
    templates.ExecuteTemplate(w, "create_chat_room.html", cur_struct)
  }
}

func NewChatHandler(db *sql.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
      w.Write([]byte("<b>Bad Method</b>"))
      return
    }
    my_url := r.URL.Path
    password, username, is_valid := URLToCredentials(my_url)
    if !is_valid {
      w.Write([]byte("<b>Bad URL format</b>"))
      return
    }
    is_valid = EvaluatePassword(&password, &username, db)
    if !is_valid {
      w.Write([]byte("<b>Not allowed to be here</b>"))
      return
    }
    rotated_link, err := CredentialsToURL(password, &username, db)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    room_name := r.FormValue("room_name")
    is_valid = GoodUsername(room_name)
    if !is_valid {
      w.Write([]byte(`<b>Bad room name</b><br><a href="../chat_page/` + rotated_link + `">Go Home</a>`))
      return
    }
    var alrd_room_name string
    content := db.QueryRow("SELECT name FROM chat_room WHERE name = ?;", room_name)
    err = content.Scan(&alrd_room_name)
    if err == nil {
      w.Write([]byte("<b>Room name already taken</b>"))
      return
    }
    users := r.FormValue("users")
    fmt.Println("users: ", users)
    users += ","
    var query_cur_usr string
    cur_usr := ""
    for i := 0; i < len(users); i++ {
      if users[i] != ',' {
        cur_usr += string(users[i])
      } else {
        is_valid = GoodUsername(cur_usr)
        if !is_valid {
          w.Write([]byte(`<b>Bad username</b><br><a href="../chat_page/` + rotated_link + `">Go Home</a>`))
          return
        }
        fmt.Println("cur_usr: ", cur_usr)
        content = db.QueryRow("SELECT username FROM credentials WHERE username=?;", cur_usr)
        err = content.Scan(&query_cur_usr)
        if err != nil {
          fmt.Println(err)
          w.Write([]byte("<b>User " + cur_usr + " does not exist</b>"))
          return
        }
        _, err = db.Exec("INSERT INTO " + cur_usr + " VALUE(?);", room_name)
        if err != nil {
          fmt.Println("this error")
          fmt.Println(err)
          w.Write([]byte("<b>Something went wrong</b>"))
          return
        }
        cur_usr = ""
      }
    }
    room_password := r.FormValue("password")
    is_valid = GoodPassword(room_password)
    if !is_valid {
      w.Write([]byte("<b>Bad password</b>"))
      return
    }
    room_password, err = CreateRoomPassword(&room_password);
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    _, err = db.Exec("INSERT INTO chat_room VALUE(?);", 
                       room_name)
    if err != nil {
      fmt.Println(err)
      w.Write([]byte("<b>Something went wrong</b>"))
      return
    }
    http.Redirect(w, r, "/chat_page/" + rotated_link, http.StatusFound)
    return
  }
}

func ConnectDatabase() (*sql.DB, error) {
  var credentials = "kvv:1234@(localhost:3306)/chat_app"
  db, err := sql.Open("mysql", credentials)
  if err != nil {
    return nil, err
  }
  return db, nil
}

func main () {

  db, err := ConnectDatabase();
  if err != nil {
    fmt.Println(err)
    return
  }

  clients := &Clients{clients: make(map[string]map[*websocket.Conn]bool),
                     db: db}
  
  mux := http.NewServeMux()

  mux.HandleFunc("/", IndexHandler)

  mux.HandleFunc("/create_account/", CreateAccountHandler)
  mux.HandleFunc("/new_account/", NewAccountHandler(db))

  mux.HandleFunc("/login/", LoginHandler)
  mux.HandleFunc("/connection/", ConnectionHandler(db))
   
  mux.HandleFunc("/chat_page/", ChatPageHandler(db))

  mux.HandleFunc("/chat/", ChatHandler(db))

  mux.HandleFunc("/create_chat/", CreateChatHandler(db))

  mux.HandleFunc("/new_chat/", NewChatHandler(db))

  mux.HandleFunc("/ws/", clients.HandleWSConnection)

  fmt.Println("Starting the server on port: ", port)
  err = http.ListenAndServe(":" + port, mux)
  if err != nil {
    fmt.Println("Failed to start server")
    fmt.Println(err)
    return
  }

  return

}


