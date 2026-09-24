package harbor

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	fakeHarborUsername = "robot$vault"
	fakeHarborPassword = "Fake-Password-123"
	fakeRobotSecret    = "Fake-Robot-Secret-456"
)

var harborRobotNameRegexp = harborNameRegexp

// fakeRobot is stored like Harbor does: without the configurable robot_name_prefix.
type fakeRobot struct {
	harborModel.Robot
	stored    string
	projectID int64
	secret    string
}

type fakeUser struct {
	id       int64
	username string
	password string
}

// fakeHarbor is an in-memory Harbor v2.0 robot API over TLS.
type fakeHarbor struct {
	server *httptest.Server

	mu        sync.Mutex
	prefix    string
	nextID    int64
	robots    map[int64]*fakeRobot
	projects  map[string]int32
	users     map[int64]*fakeUser
	creates   []*harborModel.RobotCreate
	deletes   []int64
	requests  []string
	passwords []*harborModel.PasswordReq
	// staticAuth accepts fakeHarborUsername and fakeHarborPassword without a matching robot or user.
	staticAuth bool
	// onRequest, when set and returning true, has fully handled the request before authentication.
	onRequest func(w http.ResponseWriter, r *http.Request) bool
	// onCreate, when set and returning true, has fully handled the create request.
	onCreate func(w http.ResponseWriter, create *harborModel.RobotCreate) bool
	// onDelete, when set and returning true, has fully handled the delete request.
	onDelete func(w http.ResponseWriter, id int64) bool
	// onPassword, when set and returning true, has fully handled the password change request.
	onPassword func(w http.ResponseWriter, req *harborModel.PasswordReq) bool
}

func newFakeHarbor(t *testing.T) *fakeHarbor {
	t.Helper()
	f := &fakeHarbor{
		prefix:     "robot$",
		nextID:     1,
		robots:     map[int64]*fakeRobot{},
		projects:   map[string]int32{"library": 1},
		users:      map[int64]*fakeUser{},
		staticAuth: true,
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeHarbor) URL() string {
	return f.server.URL
}

func (f *fakeHarbor) CACert() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}))
}

func (f *fakeHarbor) view(r *fakeRobot) *harborModel.Robot {
	v := r.Robot
	v.Name = f.prefix + r.stored
	return &v
}

func (f *fakeHarbor) setPrefix(prefix string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prefix = prefix
}

func (f *fakeHarbor) addProject(name string, id int32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.projects[name] = id
}

// addRobot stores a robot under its stored Harbor name ("name" or "project+name").
func (f *fakeHarbor) addRobot(stored, level string, projectID int64, description string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := f.nextID
	f.nextID++
	f.robots[id] = &fakeRobot{
		Robot:     harborModel.Robot{ID: id, Level: level, Description: description},
		stored:    stored,
		projectID: projectID,
	}
	return id
}

// addPrincipalRobot stores a system robot authenticating with fakeHarborPassword and disables static auth.
func (f *fakeHarbor) addPrincipalRobot(stored string, duration int64, permissions []*harborModel.RobotPermission) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staticAuth = false
	id := f.nextID
	f.nextID++
	f.robots[id] = &fakeRobot{
		Robot:  harborModel.Robot{ID: id, Level: robotKindSystem, Duration: duration, Permissions: permissions},
		stored: stored,
		secret: fakeHarborPassword,
	}
	return id
}

// addUser stores a local user and disables static auth.
func (f *fakeHarbor) addUser(username, password string) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.staticAuth = false
	id := f.nextID
	f.nextID++
	f.users[id] = &fakeUser{id: id, username: username, password: password}
	return id
}

func (f *fakeHarbor) userPassword(id int64) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.users[id].password
}

func (f *fakeHarbor) passwordRequests() []*harborModel.PasswordReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*harborModel.PasswordReq(nil), f.passwords...)
}

// authenticate returns the user behind the credentials; ok with a nil user is a robot.
func (f *fakeHarbor) authenticate(r *http.Request) (*fakeUser, bool) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, false
	}
	if f.staticAuth && username == fakeHarborUsername && password == fakeHarborPassword {
		return nil, true
	}
	for _, robot := range f.robots {
		if robot.secret != "" && f.prefix+robot.stored == username && robot.secret == password {
			return nil, true
		}
	}
	for _, u := range f.users {
		if u.username == username && u.password == password {
			return u, true
		}
	}
	return nil, false
}

func (f *fakeHarbor) robot(id int64) (harborModel.Robot, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.robots[id]
	if !ok {
		return harborModel.Robot{}, false
	}
	return *f.view(r), true
}

func (f *fakeHarbor) renameRobot(id int64, stored string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.robots[id].stored = stored
}

func (f *fakeHarbor) robotCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.robots)
}

func (f *fakeHarbor) lastCreate() *harborModel.RobotCreate {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) == 0 {
		return nil
	}
	return f.creates[len(f.creates)-1]
}

func (f *fakeHarbor) deletedIDs() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]int64(nil), f.deletes...)
}

func (f *fakeHarbor) requestLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeHarborError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]interface{}{
		"errors": []map[string]string{{"code": http.StatusText(status), "message": msg}},
	})
}

func (f *fakeHarbor) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())

	if f.onRequest != nil && f.onRequest(w, r) {
		return
	}

	user, ok := f.authenticate(r)
	if !ok {
		writeHarborError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	path := r.URL.Path
	switch {
	case path == "/api/v2.0/robots" && r.Method == http.MethodGet:
		f.listRobots(w, r)
	case path == "/api/v2.0/robots" && r.Method == http.MethodPost:
		f.createRobot(w, r)
	case strings.HasPrefix(path, "/api/v2.0/robots/"):
		id, err := strconv.ParseInt(strings.TrimPrefix(path, "/api/v2.0/robots/"), 10, 64)
		robot, found := f.robots[id]
		if err != nil || !found {
			writeHarborError(w, http.StatusNotFound, "robot not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, f.view(robot))
		case http.MethodDelete:
			if f.onDelete != nil && f.onDelete(w, id) {
				return
			}
			delete(f.robots, id)
			f.deletes = append(f.deletes, id)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case path == "/api/v2.0/users/current" && r.Method == http.MethodGet:
		if user == nil {
			writeHarborError(w, http.StatusPreconditionFailed, "get current user not available for security context: robot")
			return
		}
		writeJSON(w, http.StatusOK, &harborModel.UserResp{UserID: user.id, Username: user.username})
	case strings.HasPrefix(path, "/api/v2.0/users/") && strings.HasSuffix(path, "/password") && r.Method == http.MethodPut:
		f.changePassword(w, r, user)
	case strings.HasPrefix(path, "/api/v2.0/projects/") && r.Method == http.MethodGet:
		if r.Header.Get("X-Is-Resource-Name") != "true" {
			writeHarborError(w, http.StatusBadRequest, "expected project name")
			return
		}
		name := strings.TrimPrefix(path, "/api/v2.0/projects/")
		id, found := f.projects[name]
		if !found {
			writeHarborError(w, http.StatusNotFound, "project not found")
			return
		}
		writeJSON(w, http.StatusOK, &harborModel.Project{Name: name, ProjectID: id})
	default:
		writeHarborError(w, http.StatusNotFound, "not found")
	}
}

func (f *fakeHarbor) listRobots(w http.ResponseWriter, r *http.Request) {
	keywords := map[string]string{}
	if q := r.URL.Query().Get("q"); q != "" {
		unescaped, err := url.QueryUnescape(q)
		if err != nil {
			writeHarborError(w, http.StatusBadRequest, "bad query")
			return
		}
		for _, kv := range strings.Split(unescaped, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k == "" || v == "" {
				writeHarborError(w, http.StatusBadRequest, "bad query")
				return
			}
			keywords[k] = v
		}
	}

	level := keywords["Level"]
	if level == "" {
		level = robotKindSystem
	}
	var projectID int64
	if level == robotKindProject {
		pid, err := strconv.ParseInt(keywords["ProjectID"], 10, 64)
		if err != nil || pid <= 0 {
			writeHarborError(w, http.StatusBadRequest, "must with project ID when to query project robots")
			return
		}
		projectID = pid
	}

	page, err := strconv.Atoi(r.URL.Query().Get("page"))
	if err != nil || page < 1 {
		page = 1
	}
	pageSize, err := strconv.Atoi(r.URL.Query().Get("page_size"))
	if err != nil || pageSize < 1 {
		pageSize = 10
	}
	if pageSize > 100 {
		writeHarborError(w, http.StatusBadRequest, "page size too large")
		return
	}

	ids := make([]int64, 0, len(f.robots))
	for id := range f.robots {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	matched := []*harborModel.Robot{}
	for _, id := range ids {
		robot := f.robots[id]
		if robot.Level != level || robot.projectID != projectID {
			continue
		}
		if name, ok := keywords["name"]; ok {
			if fuzzy, isFuzzy := strings.CutPrefix(name, "~"); isFuzzy {
				if !strings.Contains(robot.stored, fuzzy) {
					continue
				}
			} else if robot.stored != name {
				continue
			}
		}
		matched = append(matched, f.view(robot))
	}

	items := []*harborModel.Robot{}
	if start := (page - 1) * pageSize; start < len(matched) {
		items = matched[start:min(start+pageSize, len(matched))]
	}
	w.Header().Set("X-Total-Count", strconv.Itoa(len(matched)))
	writeJSON(w, http.StatusOK, items)
}

func (f *fakeHarbor) changePassword(w http.ResponseWriter, r *http.Request, user *fakeUser) {
	var req harborModel.PasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeHarborError(w, http.StatusBadRequest, "bad body")
		return
	}
	f.passwords = append(f.passwords, &req)

	if f.onPassword != nil && f.onPassword(w, &req) {
		return
	}

	id, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v2.0/users/"), "/password"), 10, 64)
	if err != nil || user == nil || user.id != id {
		writeHarborError(w, http.StatusForbidden, "forbidden")
		return
	}
	if req.OldPassword != user.password {
		writeHarborError(w, http.StatusForbidden, "Current password is incorrect")
		return
	}
	if !fakePasswordPolicy(req.NewPassword) {
		writeHarborError(w, http.StatusBadRequest, "the password or secret must be 8-128, inclusively, characters long with at least 1 uppercase letter, 1 lowercase letter and 1 number")
		return
	}
	if req.NewPassword == user.password {
		writeHarborError(w, http.StatusBadRequest, "New password is identical to old password")
		return
	}
	user.password = req.NewPassword
	w.WriteHeader(http.StatusOK)
}

func fakePasswordPolicy(p string) bool {
	return len(p) >= 8 && len(p) <= 128 && strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") &&
		strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(p, "0123456789")
}

func (f *fakeHarbor) createRobot(w http.ResponseWriter, r *http.Request) {
	var create harborModel.RobotCreate
	if err := json.NewDecoder(r.Body).Decode(&create); err != nil {
		writeHarborError(w, http.StatusBadRequest, "bad body")
		return
	}
	f.creates = append(f.creates, &create)

	if f.onCreate != nil && f.onCreate(w, &create) {
		return
	}

	if !harborRobotNameRegexp.MatchString(create.Name) {
		writeHarborError(w, http.StatusBadRequest, "robot name is not in lower case or contains illegal characters")
		return
	}
	if len(create.Permissions) == 0 || create.Duration < 1 {
		writeHarborError(w, http.StatusBadRequest, "bad request")
		return
	}

	stored := create.Name
	var projectID int64
	switch create.Level {
	case robotKindSystem:
	case robotKindProject:
		if len(create.Permissions) != 1 {
			writeHarborError(w, http.StatusBadRequest, "bad request permission")
			return
		}
		pid, ok := f.projects[create.Permissions[0].Namespace]
		if !ok {
			writeHarborError(w, http.StatusNotFound, "project not found")
			return
		}
		stored = create.Permissions[0].Namespace + "+" + create.Name
		projectID = int64(pid)
	default:
		writeHarborError(w, http.StatusBadRequest, "bad request error level input")
		return
	}
	if len(stored) > harborNameMaxLen {
		writeHarborError(w, http.StatusInternalServerError, "value too long for type character varying(255)")
		return
	}

	id := f.nextID
	f.nextID++
	f.robots[id] = &fakeRobot{
		Robot: harborModel.Robot{
			ID:          id,
			Level:       create.Level,
			Description: create.Description,
			Duration:    create.Duration,
			Permissions: create.Permissions,
		},
		stored:    stored,
		projectID: projectID,
		secret:    fakeRobotSecret,
	}

	writeJSON(w, http.StatusCreated, &harborModel.RobotCreated{ID: id, Name: f.prefix + stored, Secret: fakeRobotSecret})
}
