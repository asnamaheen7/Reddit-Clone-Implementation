package main

import (
    "bufio"
    "fmt"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/asynkron/protoactor-go/actor"
)

// Message Types
type CreateUser struct {
    Username string
}

type CreateSubreddit struct {
    Name string
}

type JoinSubreddit struct {
    SubredditName string
    Username      string
}

type CreatePost struct {
    SubredditName string
    Title         string
    Content       string
    Author        string
}

type AddComment struct {
    PostID   string
    Content  string
    Author   string
    ParentID string
}

type VotePost struct {
    PostID   string
    IsUpvote bool
}

type SendMessage struct {
    From    string
    To      string
    Content string
}

type DisplayMessages struct {
    Username string
}

// Data Structures
type Post struct {
    ID           string
    Title        string
    Content      string
    Author       string
    Comments     []*Comment
    Votes        int
    CommentCount int
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
    From      string
    To        string
    Content   string
    Timestamp time.Time
}

// Actor Types
type RedditActor struct {
    users      map[string]*actor.PID
    subreddits map[string]*actor.PID
}

type SubredditActor struct {
    name        string
    posts       map[string]*Post
    members     []string
    postCounter int
    mutex       sync.Mutex
}

type UserActor struct {
    username   string
    messages   []Message
    subreddits []string
    mutex      sync.Mutex
}

// RedditActor methods
func (r *RedditActor) Receive(context actor.Context) {
    switch msg := context.Message().(type) {
    case *actor.Started:
        r.users = make(map[string]*actor.PID)
        r.subreddits = make(map[string]*actor.PID)
        fmt.Println("Reddit actor system started")

    case *CreateUser:
        if _, exists := r.users[msg.Username]; !exists {
            props := actor.PropsFromProducer(func() actor.Actor {
                return &UserActor{
                    username:   msg.Username,
                    messages:   []Message{},
                    subreddits: []string{},
                }
            })
            pid := context.Spawn(props)
            r.users[msg.Username] = pid
            fmt.Printf("User '%s' created successfully\n", msg.Username)
            context.Respond("User registered successfully")
        } else {
            context.Respond("Username already exists")
        }

    case *CreateSubreddit:
        if _, exists := r.subreddits[msg.Name]; !exists {
            props := actor.PropsFromProducer(func() actor.Actor {
                return &SubredditActor{
                    name:        msg.Name,
                    posts:       make(map[string]*Post),
                    members:     []string{},
                    postCounter: 0,
                }
            })
            pid := context.Spawn(props)
            r.subreddits[msg.Name] = pid
            context.Respond(fmt.Sprintf("Subreddit '%s' created successfully", msg.Name))
        } else {
            context.Respond("Subreddit already exists")
        }

    case *JoinSubreddit:
        if pid, exists := r.subreddits[msg.SubredditName]; exists {
            result, err := context.RequestFuture(pid, msg, 5*time.Second).Result()
            if err == nil {
                context.Respond(result)
            } else {
                context.Respond("Error joining subreddit")
            }
        } else {
            context.Respond("Subreddit not found")
        }

    case *DisplayMessages:
        if userPID, exists := r.users[msg.Username]; exists {
            result, err := context.RequestFuture(userPID, msg, 5*time.Second).Result()
            if err == nil {
                context.Respond(result)
            } else {
                context.Respond("Error displaying messages")
            }
        } else {
            context.Respond("User not found")
        }

    case *CreatePost:
        if pid, exists := r.subreddits[msg.SubredditName]; exists {
            result, err := context.RequestFuture(pid, msg, 5*time.Second).Result()
            if err == nil {
                context.Respond(result)
            } else {
                context.Respond("Error creating post")
            }
        } else {
            context.Respond("Subreddit not found")
        }

    case *AddComment:
        parts := strings.SplitN(msg.PostID, "_", 2)
        if len(parts) < 2 {
            context.Respond("Invalid post ID format")
            return
        }
        subredditName := parts[0]
        
        if pid, exists := r.subreddits[subredditName]; exists {
            result, err := context.RequestFuture(pid, msg, 5*time.Second).Result()
            if err == nil {
                context.Respond(result)
            } else {
                context.Respond("Error adding comment")
            }
        } else {
            context.Respond("Subreddit not found")
        }

    case *VotePost:
        parts := strings.SplitN(msg.PostID, "_", 2)
        if len(parts) < 2 {
            context.Respond("Invalid post ID format")
            return
        }
        subredditName := parts[0]
        if pid, exists := r.subreddits[subredditName]; exists {
            result, err := context.RequestFuture(pid, msg, 5*time.Second).Result()
            if err == nil {
                context.Respond(result)
            } else {
                context.Respond("Error recording vote")
            }
        } else {
            context.Respond("Subreddit not found")
        }
    }
}


// SubredditActor methods
func (s *SubredditActor) Receive(context actor.Context) {
    switch msg := context.Message().(type) {
    case *actor.Started:
        return

    case *JoinSubreddit:
        s.mutex.Lock()
        defer s.mutex.Unlock()
        for _, member := range s.members {
            if member == msg.Username {
                context.Respond("User is already a member")
                return
            }
        }
        s.members = append(s.members, msg.Username)
        context.Respond("Joined successfully")

    case *CreatePost:
        s.mutex.Lock()
        defer s.mutex.Unlock()
        isMember := false
        for _, member := range s.members {
            if member == msg.Author {
                isMember = true
                break
            }
        }
        if !isMember {
            context.Respond("Error: Must be a member to post")
            return
        }
        s.postCounter++
        postID := fmt.Sprintf("%s_%d", s.name, s.postCounter)
        post := &Post{
            ID:           postID,
            Title:        msg.Title,
            Content:      msg.Content,
            Author:       msg.Author,
            Comments:     []*Comment{},
            Votes:        0,
            CommentCount: 0,
        }
        s.posts[postID] = post
        context.Respond(fmt.Sprintf("Post created successfully. Post ID: %s", postID))

    case *AddComment:
        s.mutex.Lock()
        defer s.mutex.Unlock()

        post, exists := s.posts[msg.PostID]
        if !exists {
            context.Respond("Post not found")
            return
        }

        commentID := fmt.Sprintf("%s_c%d", msg.PostID, len(post.Comments)+1)
        comment := &Comment{
            ID:       commentID,
            Content:  msg.Content,
            Author:   msg.Author,
            Replies:  []*Comment{},
            PostID:   msg.PostID,
            ParentID: msg.ParentID,
        }

        if msg.ParentID == "" {
            post.Comments = append(post.Comments, comment)
            post.CommentCount++
            context.Respond(fmt.Sprintf("Comment added successfully. Comment ID: %s", commentID))
        } else {
            parentComment := s.findComment(post.Comments, msg.ParentID)
            if parentComment == nil {
                context.Respond("Parent comment not found")
                return
            }
            parentComment.Replies = append(parentComment.Replies, comment)
            post.CommentCount++
            context.Respond(fmt.Sprintf("Reply added successfully. Reply ID: %s", commentID))
        }

    case *VotePost:
        s.mutex.Lock()
        defer s.mutex.Unlock()
        if post, exists := s.posts[msg.PostID]; exists {
            if msg.IsUpvote {
                post.Votes++
            } else {
                post.Votes--
            }
            context.Respond(fmt.Sprintf("Vote recorded for post ID '%s'. Total Votes: %d", post.ID, post.Votes))
        } else {
            context.Respond(fmt.Sprintf("Post ID '%s' not found", msg.PostID))
        }
    }
}

// Helper method to find a comment
func (s *SubredditActor) findComment(comments []*Comment, commentID string) *Comment {
    for _, comment := range comments {
        if comment.ID == commentID {
            return comment
        }
        if found := s.findComment(comment.Replies, commentID); found != nil {
            return found
        }
    }
    return nil
}

// UserActor methods
func (u *UserActor) Receive(context actor.Context) {
    switch msg := context.Message().(type) {
    case *SendMessage:
        u.mutex.Lock()
        defer u.mutex.Unlock()
        message := Message{
            From:      msg.From,
            To:        msg.To,
            Content:   msg.Content,
            Timestamp: time.Now(),
        }
        u.messages = append(u.messages, message)
        context.Respond("Message sent successfully")

    case *DisplayMessages:
        u.mutex.Lock()
        defer u.mutex.Unlock()
        if len(u.messages) == 0 {
            context.Respond("No messages available.")
        } else {
            var output strings.Builder
            output.WriteString("Messages:\n")
            for _, message := range u.messages {
                output.WriteString(fmt.Sprintf("From: %s, Content: %s, Time: %s\n",
                    message.From, message.Content, message.Timestamp.Format(time.RFC822)))
            }
            context.Respond(output.String())
        }
    }
}// Main function
func main() {
    system := actor.NewActorSystem()

    redditActor := &RedditActor{}
    props := actor.PropsFromProducer(func() actor.Actor {
        return redditActor
    })
    pid := system.Root.Spawn(props)

    reader := bufio.NewReader(os.Stdin)
for {
        fmt.Println("\nChoose an action:")
        fmt.Println("1. Create Account")
        fmt.Println("2. Create Subreddit")
        fmt.Println("3. Join Subreddit")
        fmt.Println("4. Post in Subreddit")
        fmt.Println("5. Comment on Post")
        fmt.Println("6. Reply to Comment")
        fmt.Println("7. Send Message")
        fmt.Println("8. Display Messages")
        fmt.Println("9. Upvote Post")
        fmt.Println("10. Downvote Post")
        fmt.Println("11. Exit")
        fmt.Print("Enter your choice: ")

      input, _ := reader.ReadString('\n')
        input = strings.TrimSpace(input)

        choice, err := strconv.Atoi(input)
        if err != nil {
            fmt.Println("Invalid input. Please enter a number.")
            continue
        }

        switch choice {
        case 1: // Create Account
            fmt.Print("Enter username: ")
            username, _ := reader.ReadString('\n')
            username = strings.TrimSpace(username)

            result, err := system.Root.RequestFuture(pid, &CreateUser{Username: username}, 5*time.Second).Result()
            if err == nil {
                fmt.Println(result)
            } else {
                fmt.Println("Error creating user")
            }

        case 2: // Create Subreddit
            fmt.Print("Enter subreddit name: ")
            name, _ := reader.ReadString('\n')
            name = strings.TrimSpace(name)

            result, err := system.Root.RequestFuture(pid, &CreateSubreddit{Name: name}, 5*time.Second).Result()
            if err == nil {
                fmt.Println(result)
            } else {
                fmt.Println("Error creating subreddit")
            }

        case 3: // Join Subreddit
            fmt.Print("Enter your username: ")
            username, _ := reader.ReadString('\n')
            username = strings.TrimSpace(username)

            fmt.Print("Enter subreddit name to join: ")
            subreddit, _ := reader.ReadString('\n')
            subreddit = strings.TrimSpace(subreddit)

            result, err := system.Root.RequestFuture(pid, &JoinSubreddit{
                SubredditName: subreddit,
                Username:      username,
            }, 5*time.Second).Result()
            if err == nil {
                fmt.Println(result)
            } else {
                fmt.Println("Error joining subreddit")
            }

        case 4: // Post in Subreddit
            fmt.Print("Enter your username: ")
            username, _ := reader.ReadString('\n')
            username = strings.TrimSpace(username)

            fmt.Print("Enter subreddit name: ")
            subreddit, _ := reader.ReadString('\n')
            subreddit = strings.TrimSpace(subreddit)

            fmt.Print("Enter post title: ")
            title, _ := reader.ReadString('\n')
            title = strings.TrimSpace(title)

            fmt.Print("Enter post content: ")
            content, _ := reader.ReadString('\n')
            content = strings.TrimSpace(content)

            result, err := system.Root.RequestFuture(pid, &CreatePost{
                SubredditName: subreddit,
                Title:         title,
                Content:       content,
                Author:        username,
            }, 5*time.Second).Result()
            if err == nil {
                fmt.Println(result)
            } else {
                fmt.Println("Error creating post")
            }

        case 5, 6: // Comment/Reply to Post
            fmt.Print("Enter your username: ")
            username, _ := reader.ReadString('\n')
            username = strings.TrimSpace(username)

            fmt.Print("Enter post ID: ")
            postID, _ := reader.ReadString('\n')
            postID = strings.TrimSpace(postID)

            var parentID string
            if choice == 6 {
                fmt.Print("Enter parent comment ID: ")
                parentID, _ = reader.ReadString('\n')
                parentID = strings.TrimSpace(parentID)
            }

            fmt.Print("Enter comment content: ")
            content, _ := reader.ReadString('\n')
            content = strings.TrimSpace(content)

            result, err := system.Root.RequestFuture(pid, &AddComment{
                PostID:   postID,
                Content:  content,
                Author:   username,
                ParentID: parentID,
            }, 5*time.Second).Result()
            if err == nil {
                fmt.Println(result)
            } else {
                fmt.Println("Error adding comment")
            }

       case 7: // Send Message
            fmt.Print("Enter your username: ")
            username, _ := reader.ReadString('\n')
            username = strings.TrimSpace(username)

            fmt.Print("Enter recipient username: ")
            recipient, _ := reader.ReadString('\n')
            recipient = strings.TrimSpace(recipient)

            fmt.Print("Enter message content: ")
            content, _ := reader.ReadString('\n')
            content = strings.TrimSpace(content)

            // Access users map from the RedditActor instance
            if recipientPID, exists := redditActor.users[recipient]; exists {
                result, err := system.Root.RequestFuture(recipientPID, &SendMessage{
                    From:    username,
                    To:      recipient,
                    Content: content,
                }, 5*time.Second).Result()
                if err == nil {
                    fmt.Println(result)
                } else {
                    fmt.Println("Error sending message:", err)
                }
            } else {
                fmt.Println("Recipient not found")
            }
case 8: // Display Messages
    fmt.Print("Enter your username: ")
    username, _ := reader.ReadString('\n')
    username = strings.TrimSpace(username)

    result, err := system.Root.RequestFuture(pid, &DisplayMessages{
        Username: username,
    }, 5*time.Second).Result()

    if err == nil {
        fmt.Println(result)
    } else {
        fmt.Println("Error displaying messages")
    }

case 9, 10: // Upvote/Downvote Post
    fmt.Print("Enter post ID: ")
            postID, _ := reader.ReadString('\n')
            postID = strings.TrimSpace(postID)

            isUpvote := true
            result, err := system.Root.RequestFuture(pid, &VotePost{
                PostID:   postID,
                IsUpvote: isUpvote,
            }, 5*time.Second).Result()
            if err == nil {
                fmt.Println(result)
            } else {
                fmt.Printf("Error recording vote: %v\n", err)
            }


        case 11: // Exit
            fmt.Println("Goodbye!")
            return

        default:
            fmt.Println("Invalid choice. Please try again.")
        }
    }
}


// Additional helper functions

func (s *SubredditActor) validateMember(username string) bool {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    for _, member := range s.members {
        if member == username {
            return true
        }
    }
    return false
}

func (s *SubredditActor) ListPosts() string {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    var output strings.Builder
    output.WriteString(fmt.Sprintf("\nPosts in %s:\n", s.name))
    
    if len(s.posts) == 0 {
        output.WriteString("No posts yet.\n")
        return output.String()
    }
    
    for _, post := range s.posts {
        output.WriteString(fmt.Sprintf("ID: %s\nTitle: %s\nAuthor: %s\nVotes: %d\nComments: %d\n\n",
            post.ID, post.Title, post.Author, post.Votes, len(post.Comments)))
    }
    return output.String()
}

// Error types for better error handling
type SubredditError struct {
    Message string
}

func (e *SubredditError) Error() string {
    return e.Message
}

type PostError struct {
    Message string
}

func (e *PostError) Error() string {
    return e.Message
}

// Additional validation methods
func (s *SubredditActor) validatePost(postID string) (*Post, error) {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    post, exists := s.posts[postID]
    if !exists {
        return nil, &PostError{Message: "Post not found"}
    }
    return post, nil
}

func (u *UserActor) validateSubscription(subredditName string) bool {
    u.mutex.Lock()
    defer u.mutex.Unlock()
    
    for _, sub := range u.subreddits {
        if sub == subredditName {
            return true
        }
    }
    return false
}

// Initialize function for testing
func InitializeTestSystem() (*actor.ActorSystem, *actor.PID) {
    system := actor.NewActorSystem()
    props := actor.PropsFromProducer(func() actor.Actor {
        return &RedditActor{}
    })
    pid := system.Root.Spawn(props)
    return system, pid
}

// Additional utility functions for post management
func (s *SubredditActor) GetPost(postID string) (*Post, error) {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    post, exists := s.posts[postID]
    if !exists {
        return nil, &PostError{Message: "Post not found"}
    }
    return post, nil
}

func (s *SubredditActor) DeletePost(postID string, username string) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    post, exists := s.posts[postID]
    if !exists {
        return &PostError{Message: "Post not found"}
    }
    
    if post.Author != username {
        return &PostError{Message: "Not authorized to delete this post"}
    }
    
    delete(s.posts, postID)
    return nil
}

func (s *SubredditActor) UpdatePost(postID string, username string, newContent string) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    post, exists := s.posts[postID]
    if !exists {
        return &PostError{Message: "Post not found"}
    }
    
    if post.Author != username {
        return &PostError{Message: "Not authorized to update this post"}
    }
    
    post.Content = newContent
    return nil
}

// Message formatting helper
func formatComment(comment *Comment, level int) string {
    indent := strings.Repeat("  ", level)
    result := fmt.Sprintf("%s- %s (by %s)\n", indent, comment.Content, comment.Author)
    
    for _, reply := range comment.Replies {
        result += formatComment(reply, level+1)
    }
    return result
}

func (post *Post) FormatWithComments() string {
    var output strings.Builder
    
    output.WriteString(fmt.Sprintf("Post: %s\n", post.Title))
    output.WriteString(fmt.Sprintf("Author: %s\n", post.Author))
    output.WriteString(fmt.Sprintf("Content: %s\n", post.Content))
    output.WriteString(fmt.Sprintf("Votes: %d\n", post.Votes))
    output.WriteString("\nComments:\n")
    
    if len(post.Comments) == 0 {
        output.WriteString("No comments yet.\n")
    } else {
        for _, comment := range post.Comments {
            output.WriteString(formatComment(comment, 0))
        }
    }
    
    return output.String()
}
