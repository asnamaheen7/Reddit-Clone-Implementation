package main

import (
	"bufio"
	"bytes"
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
	"net/http"
	"os"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)

	// Ask for client ID at startup
	fmt.Print("Enter Client ID (e.g., 1, 2, etc.): ")
	clientIDInput, _ := reader.ReadString('\n')
	clientIDInput = strings.TrimSpace(clientIDInput)
	clientID := clientIDInput

	fmt.Printf("\nClient %s: Welcome! Choose an action from the list below.\n", clientID)

	for {
		fmt.Printf("\nClient %s: Choose an action:\n", clientID)
		fmt.Println(`
1.  Generate RSA Keys
2.  Create Account
3.  Create Subreddit
4.  Join Subreddit
5.  Create Post in Subreddit
6.  View All Subreddits
7.  View All Posts in a Subreddit
8.  Comment on Post
9.  Reply to Comment
10. Upvote Post
11. Downvote Post
12. Send Message
13. Display Messages
14. Retrieve Post with Signature Verification
15. Exit
`)

		fmt.Printf("Client %s: Enter your choice: ", clientID)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		switch input {
		case "1":
			privateKey, publicKey, err := generateKeys()
			if err != nil {
				fmt.Printf("Client %s: Error generating keys: %v\n", clientID, err)
				continue
			}
			fmt.Printf("Client %s: Generated Private Key:\n%s\n", clientID, privateKey)
			fmt.Printf("Client %s: Generated Public Key:\n%s\n", clientID, publicKey)

		case "2":
			fmt.Printf("Client %s: Enter username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Paste your public key (PEM format). Press Enter twice to finish:\n", clientID)
			publicKey := readMultilineInput(reader)

			data := map[string]interface{}{"Username": username, "PublicKey": publicKey}
			sendPostRequest(clientID, "http://localhost:8080/users", data)

		case "3":
			fmt.Printf("Client %s: Enter subreddit name: ", clientID)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)

			data := map[string]interface{}{"Name": name}
			sendPostRequest(clientID, "http://localhost:8080/subreddits", data)

		case "4":
			fmt.Printf("Client %s: Enter your username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Enter subreddit name: ", clientID)
			subreddit, _ := reader.ReadString('\n')
			subreddit = strings.TrimSpace(subreddit)

			data := map[string]interface{}{"Username": username, "SubredditName": subreddit}
			sendPostRequest(clientID, "http://localhost:8080/subreddits/join", data)

		case "5": // Create Post in Subreddit
			fmt.Printf("Client %s: Enter your username: ", clientID)
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)

			fmt.Printf("Client %s: Enter subreddit name: ", clientID)
			subreddit, _ := reader.ReadString('\n')
			subreddit = strings.TrimSpace(subreddit)

			fmt.Printf("Client %s: Enter post title: ", clientID)
			title, _ := reader.ReadString('\n')
			title = strings.TrimSpace(title)

			fmt.Printf("Client %s: Enter post content: ", clientID)
			content, _ := reader.ReadString('\n')
			content = strings.TrimSpace(content)

			fmt.Printf("Client %s: Paste your private key (PEM format). Press Enter twice to finish:\n", clientID)
			privateKey := readMultilineInput(reader)

			createPost(clientID, username, subreddit, title, content, privateKey)

		case "6":
			url := "http://localhost:8080/subreddits"
			sendGetRequest(clientID, url)

		case "7":
			fmt.Printf("Client %s: Enter subreddit name: ", clientID)
			subredditName, _ := reader.ReadString('\n')
			subredditName = strings.TrimSpace(subredditName)

			url := fmt.Sprintf("http://localhost:8080/subreddits/%s/posts", subredditName)
			sendGetRequest(clientID, url)
case "8":
    fmt.Printf("Client %s: Enter your username: ", clientID)
    username, _ := reader.ReadString('\n')
    username = strings.TrimSpace(username)

    fmt.Printf("Client %s: Enter post ID: ", clientID)
    postID, _ := reader.ReadString('\n')
    postID = strings.TrimSpace(postID)

    fmt.Printf("Client %s: Enter comment content: ", clientID)
    content, _ := reader.ReadString('\n')
    content = strings.TrimSpace(content)

    data := map[string]interface{}{
        "PostID":   postID,
        "Content":  content,
        "Author":   username,
        "ParentID": "",
    }
    sendPostRequest(clientID, "http://localhost:8080/comments", data)

case "9":
    fmt.Printf("Client %s: Enter your username: ", clientID)
    username, _ := reader.ReadString('\n')
    username = strings.TrimSpace(username)

    fmt.Printf("Client %s: Enter post ID: ", clientID)
    postID, _ := reader.ReadString('\n')
    postID = strings.TrimSpace(postID)

    fmt.Printf("Client %s: Enter comment content: ", clientID)
    content, _ := reader.ReadString('\n')
    content = strings.TrimSpace(content)

    fmt.Printf("Client %s: Enter parent comment ID: ", clientID)
    parentID, _ := reader.ReadString('\n')
    parentID = strings.TrimSpace(parentID)

    data := map[string]interface{}{
        "PostID":   postID,
        "Content":  content,
        "Author":   username,
        "ParentID": parentID,
    }
    sendPostRequest(clientID, "http://localhost:8080/comments", data)

case "10":
    fmt.Printf("Client %s: Enter post ID: ", clientID)
    postID, _ := reader.ReadString('\n')
    postID = strings.TrimSpace(postID)

    data := map[string]interface{}{
        "PostID":   postID,
        "IsUpvote": true,
    }
    sendPostRequest(clientID, "http://localhost:8080/votes", data)

case "11":
    fmt.Printf("Client %s: Enter post ID: ", clientID)
    postID, _ := reader.ReadString('\n')
    postID = strings.TrimSpace(postID)

    data := map[string]interface{}{
        "PostID":   postID,
        "IsUpvote": false,
    }
    sendPostRequest(clientID, "http://localhost:8080/votes", data)

case "12": // Send a message
    fmt.Printf("Client %s: Enter your username: ", clientID)
    from, _ := reader.ReadString('\n')
    from = strings.TrimSpace(from)

    fmt.Printf("Client %s: Enter recipient username: ", clientID)
    to, _ := reader.ReadString('\n')
    to = strings.TrimSpace(to)

    fmt.Printf("Client %s: Enter message content: ", clientID)
    content, _ := reader.ReadString('\n')
    content = strings.TrimSpace(content)

    data := map[string]interface{}{
        "From":    from,
        "To":      to,
        "Content": content,
    }
    sendPostRequest(clientID, "http://localhost:8080/messages/send", data)

case "13": // Display messages
    fmt.Printf("Client %s: Enter your username: ", clientID)
    username, _ := reader.ReadString('\n')
    username = strings.TrimSpace(username)

    data := map[string]interface{}{
        "Username": username,
    }
    sendPostRequest(clientID, "http://localhost:8080/messages/display", data)


case "14": // Retrieve post with signature verification
    fmt.Printf("Client %s: Enter post ID: ", clientID)
    postID, _ := reader.ReadString('\n')
    postID = strings.TrimSpace(postID)

    url := fmt.Sprintf("http://localhost:8080/posts/%s", postID)
    sendGetRequest(clientID, url)

case "15":
    fmt.Printf("Client %s: Exiting. Goodbye!\n", clientID)
    return


		default:
			fmt.Printf("Client %s: Invalid choice. Please try again.\n", clientID)
		}
	}
}
func createPost(clientID, username, subreddit, title, content, privateKey string) {
    // Parse the private key
    parsedPrivateKey, err := parsePrivateKey(privateKey)
    if err != nil {
        fmt.Printf("Client %s: Invalid private key: %v\n", clientID, err)
        return
    }

    // Hash the content
    hash := sha256.Sum256([]byte(content))

    // Generate the signature
    signature, err := rsa.SignPKCS1v15(rand.Reader, parsedPrivateKey, crypto.SHA256, hash[:])
    if err != nil {
        fmt.Printf("Client %s: Error signing post: %v\n", clientID, err)
        return
    }
    encodedSignature := base64.StdEncoding.EncodeToString(signature)

    // Debugging Logs
    fmt.Printf("Client %s: Content to Sign: %s\n", clientID, content)
    fmt.Printf("Client %s: Generated Hash: %x\n", clientID, hash)
    fmt.Printf("Client %s: Generated Signature (Base64): %s\n", clientID, encodedSignature)

    // Create the post payload
    data := map[string]interface{}{
        "Username":      username,
        "SubredditName": subreddit,
        "Title":         title,
        "Content":       content,
        "Signature":     encodedSignature,
    }

    // Send the request
    sendPostRequest(clientID, "http://localhost:8080/posts", data)
}

func readMultilineInput(reader *bufio.Reader) string {
	var input string
	for {
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) == "" {
			break
		}
		input += line
	}
	return input
}

func sendPostRequest(clientID string, url string, data map[string]interface{}) {
    jsonData, _ := json.Marshal(data)
    fmt.Printf("Client %s: Sending POST request to %s with payload: %s\n", clientID, url, string(jsonData))

    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        fmt.Printf("Client %s: Error creating request: %v\n", clientID, err)
        return
    }

    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Client-ID", clientID)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("Client %s: Error sending POST request: %v\n", clientID, err)
        return
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("Client %s: Response: %v\n", clientID, result)
}

func sendGetRequest(clientID, url string) {
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        fmt.Printf("Client %s: Error creating GET request: %v\n", clientID, err)
        return
    }
    req.Header.Set("Client-ID", clientID)
    
    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Printf("Client %s: Error sending GET request: %v\n", clientID, err)
        return
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("Client %s: Response: %v\n", clientID, result)
}


func generateKeys() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privatePem := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privatePem), string(publicPem), nil
}

func parsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}


func signPost(content string, privateKey *rsa.PrivateKey) (string, error) {
	hash := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func clientLogger(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Suppress automatic logging for all endpoints
        next.ServeHTTP(w, r)
    })
}
