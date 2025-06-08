
package main

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "errors"
    "fmt"
    "log"
    "net/http"
    "sync"   

    "github.com/gorilla/mux"
)



// Models
type User struct {
    Username  string
    PublicKey string // Store the public key as a string
}

type Comment struct {
	ID       string
	Content  string
	Author   string
	Replies  []*Comment
	PostID   string
	ParentID string
}

type Message struct {
	From    string
	To      string
	Content string
}

type Subreddit struct {
	Name        string
	Members     []string
	Posts       map[string]*Post
	PostCounter int
	CommentMap  map[string]int
}
type Post struct {
    ID           string
    Title        string
    Content      string
    Author       string
    Comments     []*Comment
    Votes        int
    CommentCount int
    Signature    string // Store the signature as a string
}


// Global Data
var (
	users      = make(map[string]User)
	subreddits = make(map[string]*Subreddit)
	messages   = make(map[string][]Message)
	mutex      = &sync.Mutex{}
)
// REST Handlers

func clientLogger(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Suppress logging for specific endpoints
        suppressedEndpoints := map[string]bool{
            "/users": true, // Suppress logging for /users
        }

        // Skip logging for suppressed endpoints
        if suppressedEndpoints[r.URL.Path] {
            next.ServeHTTP(w, r) // Process the request without logging
            return
        }

        // Log other requests
        clientID := r.Header.Get("Client-ID")
        if clientID == "" {
            clientID = "Unknown"
        }
        log.Printf("Request from Client %s: %s %s", clientID, r.Method, r.URL.Path)

        next.ServeHTTP(w, r)
    })
}


// Register a new user
func registerUserHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    username := req["Username"]
    publicKey := req["PublicKey"]

    mutex.Lock()
    defer mutex.Unlock()

    if _, exists := users[username]; exists {
        http.Error(w, "Username already exists", http.StatusConflict)
        return
    }

    users[username] = User{
        Username:  username,
        PublicKey: publicKey,
    }

    log.Printf("Client: %s\nAction: User Registered\nUsername: %s\n", clientID, username)
    json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}


// Create a new subreddit
func createSubredditHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    name := req["Name"]

    mutex.Lock()
    defer mutex.Unlock()

    if _, exists := subreddits[name]; exists {
        http.Error(w, "Subreddit already exists", http.StatusConflict)
        return
    }

    subreddits[name] = &Subreddit{
        Name:        name,
        Posts:       make(map[string]*Post),
        PostCounter: 0,
    }

    log.Printf("Client: %s\nAction: Subreddit Created\nSubreddit Name: %s\n", clientID, name)
    json.NewEncoder(w).Encode(map[string]string{"message": "Subreddit created successfully"})
}

func listSubredditsHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    mutex.Lock()
    defer mutex.Unlock()

    subredditList := make([]string, 0, len(subreddits))
    for name := range subreddits {
        subredditList = append(subredditList, name)
    }

    log.Printf("Client: %s\nAction: Listing All Subreddits\nSubreddits: %v\n", clientID, subredditList)
    json.NewEncoder(w).Encode(map[string]interface{}{"Subreddits": subredditList})
}


// Join an existing subreddit
func joinSubredditHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    username := req["Username"]
    subredditName := req["SubredditName"]

    mutex.Lock()
    defer mutex.Unlock()

    subreddit, exists := subreddits[subredditName]
    if !exists {
        http.Error(w, "Subreddit not found", http.StatusNotFound)
        return
    }

    for _, member := range subreddit.Members {
        if member == username {
            json.NewEncoder(w).Encode(map[string]string{
                "message": "User already a member of the subreddit",
            })
            return
        }
    }

    subreddit.Members = append(subreddit.Members, username)
    log.Printf("Client: %s\nAction: User Joined Subreddit\nUsername: %s\nSubreddit Name: %s\n", clientID, username, subredditName)
    json.NewEncoder(w).Encode(map[string]string{
        "message": "Joined subreddit successfully",
    })
}

func createPostHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username      string `json:"Username"`
        SubredditName string `json:"SubredditName"`
        Title         string `json:"Title"`
        Content       string `json:"Content"`
        Signature     string `json:"Signature"`
    }

    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    defer mutex.Unlock()

    subreddit, exists := subreddits[req.SubredditName]
    if !exists {
        http.Error(w, "Subreddit not found", http.StatusNotFound)
        return
    }

    user, userExists := users[req.Username]
    if !userExists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    publicKey, err := parsePublicKey(user.PublicKey)
    if err != nil {
        http.Error(w, "Invalid public key", http.StatusInternalServerError)
        return
    }

    contentHash := sha256.Sum256([]byte(req.Content))
    decodedSignature, err := base64.StdEncoding.DecodeString(req.Signature)
    if err != nil {
        http.Error(w, "Invalid signature format", http.StatusBadRequest)
        return
    }

    if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, contentHash[:], decodedSignature); err != nil {
        log.Printf("Signature verification failed: %v", err)
        http.Error(w, "Signature verification failed", http.StatusUnauthorized)
        return
    }

    postID := fmt.Sprintf("p%d", subreddit.PostCounter+1)
    post := &Post{
        ID:        postID,
        Title:     req.Title,
        Content:   req.Content,
        Author:    req.Username,
        Signature: req.Signature,
        Votes:     0,
        Comments:  []*Comment{},
    }

    subreddit.Posts[postID] = post
    subreddit.PostCounter++

    log.Printf("Post created successfully with ID %s in subreddit %s by user %s", postID, req.SubredditName, req.Username)
    json.NewEncoder(w).Encode(map[string]string{"message": "Post created successfully", "postID": postID})
}

// Create a new post in a subreddit
func createPost(clientID, username, subreddit, title, content, privateKey string) {
    parsedPrivateKey, err := parsePrivateKey(privateKey)
    if err != nil {
        fmt.Printf("Client %s: Invalid private key: %v\n", clientID, err)
        return
    }

    hash := sha256.Sum256([]byte(content))
    signature, err := rsa.SignPKCS1v15(rand.Reader, parsedPrivateKey, crypto.SHA256, hash[:])
    if err != nil {
        fmt.Printf("Client %s: Error signing post: %v\n", clientID, err)
        return
    }

    encodedSignature := base64.StdEncoding.EncodeToString(signature)

    // Debugging logs
    fmt.Printf("Generated Signature (Base64): %s\n", encodedSignature)

    data := map[string]interface{}{
        "Username":      username,
        "SubredditName": subreddit,
        "Title":         title,
        "Content":       content,
        "Signature":     encodedSignature,
    }

    fmt.Printf("Payload Sent: %+v\n", data)
}

func listPostsInSubredditHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    subredditName := vars["subredditName"]

    mutex.Lock()
    defer mutex.Unlock()

    subreddit, exists := subreddits[subredditName]
    if !exists {
        log.Printf("Subreddit not found: %s", subredditName)
        http.Error(w, "Subreddit not found", http.StatusNotFound)
        return
    }

    posts := make([]map[string]interface{}, 0)
    for _, post := range subreddit.Posts {
        posts = append(posts, map[string]interface{}{
            "ID":      post.ID,
            "Title":   post.Title,
            "Author":  post.Author,
            "Votes":   post.Votes,
            "Content": post.Content,
        })
    }

    log.Printf("Listing posts in subreddit: %s", subredditName)
    json.NewEncoder(w).Encode(map[string]interface{}{"Posts": posts})
}

// Add or reply to a comment on a post
func addCommentHandler(w http.ResponseWriter, r *http.Request) {
    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        log.Printf("Error decoding request: %v", err)
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    postID := req["PostID"]
    content := req["Content"]
    author := req["Author"]
    parentID := req["ParentID"] // Can be empty for top-level comments

    mutex.Lock()
    defer mutex.Unlock()

    var post *Post
    var found bool
    for _, subreddit := range subreddits {
        if p, exists := subreddit.Posts[postID]; exists {
            post = p
            found = true
            break
        }
    }
    if !found {
        log.Printf("Action: Add Comment\nPost ID: %s\nStatus: Post not found\n", postID)
        http.Error(w, "Post not found", http.StatusNotFound)
        return
    }

    commentID := fmt.Sprintf("c%d", len(post.Comments)+1)
    comment := &Comment{
        ID:       commentID,
        Content:  content,
        Author:   author,
        PostID:   postID,
        ParentID: parentID,
        Replies:  []*Comment{},
    }

    if parentID == "" {
        post.Comments = append(post.Comments, comment)
        log.Printf("Action: Add Comment\nPost ID: %s\nComment ID: %s\nAuthor: %s\nContent: %s\n", postID, commentID, author, content)
    } else {
        parent := findComment(post.Comments, parentID)
        if parent == nil {
            log.Printf("Action: Add Reply\nPost ID: %s\nParent Comment ID: %s\nStatus: Parent not found\n", postID, parentID)
            http.Error(w, fmt.Sprintf("Parent comment not found: %s", parentID), http.StatusNotFound)
            return
        }
        parent.Replies = append(parent.Replies, comment)
        log.Printf("Action: Add Reply\nPost ID: %s\nParent Comment ID: %s\nReply ID: %s\nAuthor: %s\nContent: %s\n", postID, parentID, commentID, author, content)
    }

    json.NewEncoder(w).Encode(map[string]string{
        "message":   "Comment added successfully",
        "commentID": commentID,
    })
}


// Helper to find a comment by ID
// Recursive function to find a comment by ID in a post
func findComment(comments []*Comment, commentID string) *Comment {
    for _, comment := range comments {
        if comment.ID == commentID {
            return comment
        }
        // Recursive search in replies
        result := findComment(comment.Replies, commentID)
        if result != nil {
            return result
        }
    }
    return nil
}



// Record upvote or downvote for a post
func votePostHandler(w http.ResponseWriter, r *http.Request) {
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	postID := req["PostID"].(string)
	isUpvote := req["IsUpvote"].(bool)

	mutex.Lock()
	defer mutex.Unlock()

	for _, subreddit := range subreddits {
		if post, exists := subreddit.Posts[postID]; exists {
			if isUpvote {
				post.Votes++
			} else {
				post.Votes--
			}
			log.Printf("Vote recorded for post ID %s. Total Votes: %d", post.ID, post.Votes)
			json.NewEncoder(w).Encode(map[string]interface{}{"message": "Vote recorded successfully", "newVotes": post.Votes})
			return
		}
	}

	http.Error(w, "Post not found", http.StatusNotFound)
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var msg Message
    if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    mutex.Lock()
    defer mutex.Unlock()

    if _, exists := users[msg.To]; !exists {
        http.Error(w, "Recipient not found", http.StatusNotFound)
        return
    }

    messages[msg.To] = append(messages[msg.To], msg)
    log.Printf("Client %s sent message from %s to %s: %s", clientID, msg.From, msg.To, msg.Content)

    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Message sent successfully"})
}
func displayMessagesHandler(w http.ResponseWriter, r *http.Request) {
    clientID := r.Header.Get("Client-ID")
    if clientID == "" {
        clientID = "Unknown"
    }

    var req map[string]string
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request payload", http.StatusBadRequest)
        return
    }

    username := req["Username"]

    mutex.Lock()
    defer mutex.Unlock()

    userMessages, exists := messages[username]
    if !exists || len(userMessages) == 0 {
        log.Printf("Client: %s\nAction: Display Messages\nReceiver: %s\nMessages: No messages found\n", clientID, username)
        json.NewEncoder(w).Encode([]Message{}) // Return an empty list if no messages exist
        return
    }

    log.Printf("Client: %s\nAction: Display Messages\nReceiver: %s\nMessages: %+v\n", clientID, username, userMessages)
    json.NewEncoder(w).Encode(userMessages) // Return the messages for the user
}


func getUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    username := vars["username"]

    mutex.Lock()
    defer mutex.Unlock()

    user, exists := users[username]
    if !exists {
        http.Error(w, "User not found", http.StatusNotFound)
        return
    }

    json.NewEncoder(w).Encode(map[string]string{"PublicKey": user.PublicKey})
}
func getPostHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    postID := vars["postID"]

    mutex.Lock()
    defer mutex.Unlock()

    // Search for the post by ID
    for _, subreddit := range subreddits {
        if post, exists := subreddit.Posts[postID]; exists {
            log.Printf("Client requested post with ID: %s", postID)
            log.Printf("Post with ID %s found in subreddit %s", postID, subreddit.Name)

            // Fetch author details and their public key
            user, userExists := users[post.Author]
            if !userExists {
                http.Error(w, "Author not found", http.StatusNotFound)
                return
            }

            publicKey, err := parsePublicKey(user.PublicKey)
            if err != nil {
                log.Printf("Invalid public key for author %s: %v", post.Author, err)
                http.Error(w, "Invalid public key", http.StatusInternalServerError)
                return
            }

            // Decode the received signature
            sigBytes, err := base64.StdEncoding.DecodeString(post.Signature)
            if err != nil {
                log.Printf("Error decoding signature for post %s: %v", postID, err)
                http.Error(w, "Invalid signature format", http.StatusBadRequest)
                return
            }

            // Compute the hash of the content
            hash := sha256.Sum256([]byte(post.Content))

            // Verify the signature
            log.Printf("Server Verification - Received Signature (Base64): %s", post.Signature)
            log.Printf("Server Verification - Decoded Signature: %x", sigBytes)
            log.Printf("Server Verification - Content: %q", post.Content)
            log.Printf("Server Verification - Hash (SHA256): %x", hash)

            err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigBytes)
            if err != nil {
                log.Printf("Signature verification failed for post %s: %v", postID, err)
                http.Error(w, "Signature verification failed", http.StatusUnauthorized)
                return
            }

            log.Printf("Signature verified successfully for post %s", postID)
            json.NewEncoder(w).Encode(post)
            return
        }
    }

    http.Error(w, "Post not found", http.StatusNotFound)
}

func parsePublicKey(publicKeyStr string) (*rsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(publicKeyStr))
    if block == nil || block.Type != "PUBLIC KEY" {
        return nil, errors.New("failed to decode PEM block containing public key")
    }
    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse public key: %v", err)
    }
    rsaPub, ok := pub.(*rsa.PublicKey)
    if !ok {
        return nil, errors.New("not an RSA public key")
    }
    return rsaPub, nil
}
func parsePrivateKey(privateKeyStr string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privateKeyStr))
    if block == nil || block.Type != "PRIVATE KEY" {
        return nil, errors.New("failed to decode PEM block containing private key")
    }
    key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse private key: %v", err)
    }

    rsaPriv, ok := key.(*rsa.PrivateKey)
    if !ok {
        return nil, errors.New("not an RSA private key")
    }
    return rsaPriv, nil
}


func signPost(content string, privateKey *rsa.PrivateKey) (string, error) {
    hash := sha256.Sum256([]byte(content))
    signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
    if err != nil {
        return "", err
    }
    return base64.StdEncoding.EncodeToString(signature), nil
}

func verifyPost(content, signature string, publicKey *rsa.PublicKey) error {
    hash := sha256.Sum256([]byte(content))
    sigBytes, err := base64.StdEncoding.DecodeString(signature)
    if err != nil {
        log.Printf("Invalid signature format: %v", err)
        return fmt.Errorf("invalid signature format: %w", err)
    }

    log.Printf("Verifying content: %q", content) // Log content
    log.Printf("Public key: %v", publicKey)     // Log public key
    log.Printf("Signature bytes: %x", sigBytes) // Log raw signature bytes

    err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigBytes)
    if err != nil {
        log.Printf("Signature verification failed: %v", err)
    }
    return err
}


func fetchPublicKey(username string) *rsa.PublicKey {
    mutex.Lock()
    defer mutex.Unlock()

    user, exists := users[username]
    if !exists {
        return nil
    }

    publicKey, err := parsePublicKey(user.PublicKey)
    if err != nil {
        log.Printf("Error parsing public key for user %s: %v", username, err)
        return nil
    }

    return publicKey
}

// Example Handler Function for Posting
func handlePost(w http.ResponseWriter, r *http.Request) {
    var postRequest struct {
        Username      string `json:"Username"`
        SubredditName string `json:"SubredditName"`
        Title         string `json:"Title"`
        Content       string `json:"Content"`
        Signature     string `json:"Signature"`
    }

    // Parse the incoming JSON
    if err := json.NewDecoder(r.Body).Decode(&postRequest); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }

    // Fetch the public key for the username from the database
    publicKey := fetchPublicKey(postRequest.Username) // Replace with your actual method
    if publicKey == nil {
        http.Error(w, "Public key not found", http.StatusNotFound)
        return
    }

    // Decode the signature
    signature, err := base64.StdEncoding.DecodeString(postRequest.Signature)
    if err != nil {
        http.Error(w, "Invalid signature format", http.StatusBadRequest)
        return
    }

    // Prepare the content hash
    hash := sha256.Sum256([]byte(postRequest.Content))

    // Debug logs before verification
    log.Println("Public key used for verification:", publicKey)
    log.Println("Signature received:", postRequest.Signature)
    log.Println("Content being verified:", postRequest.Content)

    // Perform the signature verification
    if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], signature); err != nil {
        log.Println("Signature verification failed:", err)
        http.Error(w, "Signature verification failed", http.StatusUnauthorized)
        return
    }

    // Proceed with storing the post or further logic
    log.Println("Signature verified successfully!")
    w.WriteHeader(http.StatusOK)
    json.NewEncoder(w).Encode(map[string]string{"message": "Post created successfully"})
}





func main() {
    r := mux.NewRouter()

    r.HandleFunc("/users", registerUserHandler).Methods("POST")
    r.HandleFunc("/subreddits", createSubredditHandler).Methods("POST")
    r.HandleFunc("/subreddits/join", joinSubredditHandler).Methods("POST")
    r.HandleFunc("/subreddits", listSubredditsHandler).Methods("GET")
    r.HandleFunc("/subreddits/{subredditName}/posts", listPostsInSubredditHandler).Methods("GET")
    r.HandleFunc("/posts", createPostHandler).Methods("POST") // Updated reference
    r.HandleFunc("/comments", addCommentHandler).Methods("POST")
    r.HandleFunc("/votes", votePostHandler).Methods("POST")
    r.HandleFunc("/messages/send", sendMessageHandler).Methods("POST")
    r.HandleFunc("/messages/display", displayMessagesHandler).Methods("POST")
    r.HandleFunc("/users/{username}/publickey", getUserPublicKeyHandler).Methods("GET")
    r.HandleFunc("/posts/{postID}", getPostHandler).Methods("GET")

    log.Println("Server running on port 8080")
    log.Fatal(http.ListenAndServe(":8080", r))
}

