package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username                   string
	Sk_decrypt                 userlib.PKEDecKey
	Sk_sign                    userlib.DSSignKey
	Uuid_File_manager          userlib.UUID
	Symmetric_key_file_manager []byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type Invitation struct {
	Uuid_TO_file   userlib.UUID
	Recipient_name string
	Sender_name    string
	Owner_name     string
	Uuid_to_hmac   userlib.UUID
	Key_hmac_file  []byte
	Key_file       []byte
	RSA_signature  []byte
}

type File_Manager struct {
	Owned_uuid         map[string]userlib.UUID
	Owned_enc_int      map[string][2][]byte
	Owned_sharee       map[string]Sharee_list
	Owned_uuid_to_hmac map[string]userlib.UUID

	Shared_uuid         map[string]userlib.UUID
	Shared_owner_name   map[string]string
	Shared_enc_int      map[string][2][]byte
	Shared_uuid_to_hmac map[string]userlib.UUID
}

type File struct {
	Blocks   []Block
	Sym_key  []byte
	Hmac_key []byte
}

type Block struct {
	Uuid userlib.UUID
	Hmac []byte
}
type Sharee_list struct {
	List map[string]userlib.UUID
}

type Envelop struct {
	Uuid_to_invitation userlib.UUID
	Enc_sym_key        []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		err = errors.New("an empty username is provided")
		return nil, err
	}

	_, ok := userlib.KeystoreGet(username + "-enc")
	if ok {
		err = errors.New("a user with the same username exists")
		return nil, err
	}

	//Create information for user
	new_uuid := userlib.Argon2Key([]byte(password), []byte(username), 16)
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	//store user public key
	err = userlib.KeystoreSet(username+"-enc", PKEEncKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet(username+"-verify", DSVerifyKey)
	if err != nil {
		return nil, err
	}

	uuid_file_manager := uuid.New()
	sym_key_file_manager := userlib.RandomBytes(16)

	//init new user
	user := &User{
		username,
		PKEDecKey,
		DSSignKey,
		uuid_file_manager,
		sym_key_file_manager,
	}

	//process user into bytes
	user_bytes, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	//generate key for enc
	key := userlib.Argon2Key([]byte(username), []byte(password), 16)
	//encrypt new_user using symmetric key
	encrypted_user_data := userlib.SymEnc(key, userlib.RandomBytes(16), user_bytes)
	//store user encrypted data into data store
	userlib.DatastoreSet(uuid.UUID(new_uuid), encrypted_user_data)

	//Init File_Manager
	file_manager := &File_Manager{}
	file_manager.Owned_enc_int = make(map[string][2][]byte)
	file_manager.Owned_sharee = make(map[string]Sharee_list)
	file_manager.Owned_uuid = make(map[string]uuid.UUID)
	file_manager.Owned_uuid_to_hmac = make(map[string]uuid.UUID)
	file_manager.Shared_enc_int = make(map[string][2][]byte)
	file_manager.Shared_owner_name = make(map[string]string)
	file_manager.Shared_uuid = make(map[string]uuid.UUID)
	file_manager.Shared_uuid_to_hmac = make(map[string]uuid.UUID)

	//Process File_Manager to bytes
	file_manager_bytes, err := json.Marshal(file_manager)
	if err != nil {
		return nil, err
	}
	//Encrypt File_Manager
	encrypted_file_manager_bytes := userlib.SymEnc(sym_key_file_manager, userlib.RandomBytes(16), file_manager_bytes)
	//store encrypted File_Manager
	userlib.DatastoreSet(uuid_file_manager, encrypted_file_manager_bytes)

	return user, err
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	//check if user exists
	_, ok := userlib.KeystoreGet(username + "-enc")
	if !ok {
		err = errors.New("a user doesn't exist")
		return nil, err
	}

	//get user uuid
	user_uuid := userlib.Argon2Key([]byte(password), []byte(username), 16)

	//get user_enc_data
	user_enc_data, ok := userlib.DatastoreGet(uuid.UUID(user_uuid))
	if !ok {
		err = errors.New("wrong passowrd")
		return nil, err
	}

	//get decryption key
	key := userlib.Argon2Key([]byte(username), []byte(password), 16)

	//decrypt data in user_bytes
	user_bytes := userlib.SymDec(key, user_enc_data)

	//unmarshal data into json file
	var user *User = &User{}
	err = json.Unmarshal(user_bytes, user)
	if err != nil {
		return nil, err
	}

	//check if the file is modifed and user credentials invalid
	if user.Username != username {
		err = errors.New("file has been modified")
		return nil, err
	}

	return user, err
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	////***** THIS ONLY DEAL WITH THE CASE IS OWNER, CHECK NAME LATER *****/////

	/////////////////// BLOCK RELATED /////////////////////
	//Generate uuid for block
	block_uuid := uuid.New()

	//generate keys for block
	block_sym_key := userlib.RandomBytes(16)
	block_hmac_key := userlib.RandomBytes(16)

	//Encrypt block content
	enc_content := userlib.SymEnc(block_sym_key, userlib.RandomBytes(16), content)
	//hmac block content
	hmac_content, err := userlib.HMACEval(block_hmac_key, enc_content)
	if err != nil {
		return err
	}

	//store block to datastore
	userlib.DatastoreSet(block_uuid, enc_content)

	///////////// FILE RELATED /////////////
	//Init file
	var file = &File{}
	var block Block = Block{
		block_uuid,
		hmac_content,
	}
	file.Blocks = append(file.Blocks, block)
	file.Sym_key = block_sym_key
	file.Hmac_key = block_hmac_key

	//generate uuid for file
	file_uuid := uuid.New()
	//generate keys for file
	file_sym_key := userlib.RandomBytes(16)
	file_hmac_key := userlib.RandomBytes(16)
	uuid_to_hmac := uuid.New()

	//Process file into bytes
	file_bytes, err := json.Marshal(file)
	if err != nil {
		return err
	}

	//encrypt file
	file_enc := userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), file_bytes)
	//hmac file
	file_hmac, err := userlib.HMACEval(file_hmac_key, file_enc)
	if err != nil {
		return err
	}
	//store hmac to uuid_to_hmac
	userlib.DatastoreSet(uuid_to_hmac, file_hmac)
	//store file to datastore
	userlib.DatastoreSet(file_uuid, file_enc)

	//////////////// FILE_MANAGER RELATED //////////////
	//get File_Manager
	file_manager, err := GetFileManager(userdata.Uuid_File_manager, userdata.Symmetric_key_file_manager)
	if err != nil {
		return err
	}

	//Adding entry to file_manager
	file_manager.Owned_uuid[filename] = file_uuid
	file_manager.Owned_enc_int[filename] = [2][]byte{
		[]byte(file_sym_key),
		[]byte(file_hmac_key),
	}
	file_manager.Owned_uuid_to_hmac[filename] = uuid_to_hmac
	file_manager.Owned_sharee[filename] = Sharee_list{make(map[string]uuid.UUID)}

	//convert file_manager to bytes
	file_manager_bytes, err := json.Marshal(file_manager)
	if err != nil {
		return err
	}
	//Encrypt file_manager
	file_manager_enc := userlib.SymEnc(userdata.Symmetric_key_file_manager, userlib.RandomBytes(16), file_manager_bytes)

	//store back to datastore
	userlib.DatastoreSet(userdata.Uuid_File_manager, file_manager_enc)

	return nil
}

// //////////////////APPEND TO FILE//////////////////////
func (userdata *User) AppendToFile(filename string, content []byte) error {
	file_manager, err := GetFileManager(userdata.Uuid_File_manager, userdata.Symmetric_key_file_manager)
	if err != nil {
		return err
	}
	block_uuid := uuid.New()
	var file *File = &File{}

	//check if the file exist and get the file
	//if user is owner
	if uuid, exists := file_manager.Owned_uuid[filename]; exists {
		file_sym_key := file_manager.Owned_enc_int[filename][0]
		file_hmac_key := file_manager.Owned_enc_int[filename][1]
		uuid_to_hmac := file_manager.Owned_uuid_to_hmac[filename]

		//Get hmac
		hmac, ok := userlib.DatastoreGet(uuid_to_hmac)
		if !ok {
			return errors.New("can't find hmac 1")
		}

		//get file and check for integrity using hmac
		file, err = GetFile(true, uuid, file_sym_key, file_hmac_key, hmac)
		if err != nil {
			return err
		}

		//Encrypt block content
		enc_content := userlib.SymEnc(file.Sym_key, userlib.RandomBytes(16), content)
		//hmac block content
		hmac_content, err := userlib.HMACEval(file.Hmac_key, enc_content)
		if err != nil {
			return err
		}

		//store enc content to datastore
		userlib.DatastoreSet(block_uuid, enc_content)

		//append new block
		var block Block = Block{
			block_uuid,
			hmac_content,
		}
		file.Blocks = append(file.Blocks, block)
		//convert to bytes
		file_bytes, err := json.Marshal(file)
		if err != nil {
			return err
		}
		//encrypt file
		file_enc := userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), file_bytes)
		//hmac file
		file_hmac, err := userlib.HMACEval(file_hmac_key, file_enc)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(uuid_to_hmac, file_hmac)
		userlib.DatastoreSet(uuid, file_enc)

		//IF USER IS SHAREE
	} else if uuid, exists := file_manager.Shared_uuid[filename]; exists {
		file_sym_key := file_manager.Shared_enc_int[filename][0]
		file_hmac_key := file_manager.Shared_enc_int[filename][1]
		uuid_to_hmac := file_manager.Shared_uuid_to_hmac[filename]
		hmac, ok := userlib.DatastoreGet(uuid_to_hmac)

		if !ok {
			return errors.New("can't find hmac 2")
		}
		file, err = GetFile(false, uuid, file_sym_key, file_hmac_key, hmac)
		if err != nil {
			return err
		}

		//Encrypt block content
		enc_content := userlib.SymEnc(file.Sym_key, userlib.RandomBytes(16), content)
		//hmac block content
		hmac_content, err := userlib.HMACEval(file.Hmac_key, enc_content)
		if err != nil {
			return err
		}
		//store enc content to datastore
		userlib.DatastoreSet(block_uuid, enc_content)

		//append new block
		var block Block = Block{
			block_uuid,
			hmac_content,
		}
		file.Blocks = append(file.Blocks, block)
		//convert to bytes
		file_bytes, err := json.Marshal(file)
		if err != nil {
			return err
		}
		//encrypt file
		file_enc := userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), file_bytes)
		//hmac file
		file_hmac, err := userlib.HMACEval(file_hmac_key, file_enc)
		if err != nil {
			return err
		}

		uuid_file_bytes, ok := userlib.DatastoreGet(uuid)
		if !ok {
			return errors.New("can't find uuid file")
		}

		var uuid_file *userlib.UUID = &userlib.UUID{}
		err = json.Unmarshal(uuid_file_bytes, uuid_file)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(uuid_to_hmac, file_hmac)
		userlib.DatastoreSet(*uuid_file, file_enc)

	} else {
		return errors.New("append to unexisted file")
	}

	if file == nil {
		return errors.New("can not find the file")
	}

	return nil
}

//////////////////LOAD FILE////////////////////////

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	//Get file manager
	file_manager, err := GetFileManager(userdata.Uuid_File_manager, userdata.Symmetric_key_file_manager)
	if err != nil {
		return nil, err
	}

	var file *File = &File{}
	//If owner
	if uuid, exists := file_manager.Owned_uuid[filename]; exists {
		//Get data to verify and decrypt file struct
		file_sym_key := file_manager.Owned_enc_int[filename][0]
		file_hmac_key := file_manager.Owned_enc_int[filename][1]
		file_hmac, ok := userlib.DatastoreGet(file_manager.Owned_uuid_to_hmac[filename])
		if !ok {
			return nil, errors.New("can't find mac 1")
		}

		file, err = GetFile(true, uuid, file_sym_key, file_hmac_key, file_hmac)
		if err != nil {
			return nil, err
		}

		//If sharee
	} else if uuid_TO_file, exists := file_manager.Shared_uuid[filename]; exists {
		file_sym_key := file_manager.Shared_enc_int[filename][0]
		file_hmac_key := file_manager.Shared_enc_int[filename][1]
		file_hmac, ok := userlib.DatastoreGet(file_manager.Shared_uuid_to_hmac[filename])
		if !ok {
			return nil, errors.New("can't find mac 2")
		}
		if !ok {
			return nil, errors.New("cant find file")
		}

		file, err = GetFile(false, uuid_TO_file, file_sym_key, file_hmac_key, file_hmac)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, errors.New("file name not exist")
	}

	//Getting content from file
	content, err = GetContent(file)
	if err != nil {
		return nil, err
	}

	return content, err
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	//check if  recipientUsername exist
	enc_key, ok := userlib.KeystoreGet(recipientUsername + "-enc")
	if !ok {
		return uuid.Nil, errors.New("can't find username")
	}

	//Get file manager
	file_manager, err := GetFileManager(userdata.Uuid_File_manager, userdata.Symmetric_key_file_manager)
	if err != nil {
		return uuid.Nil, err
	}

	//generate uuid for invitation
	invitationPtr = uuid.New()

	//Two case: Own the file and Being Shared with the file

	var invitation *Invitation = &Invitation{}
	//check if filename exist
	/////////// If own //////////////
	if file_uuid, ok := file_manager.Owned_uuid[filename]; ok {
		//Init new uuid_TO_file
		uuid_TO_file := uuid.New()
		file_manager.Owned_sharee[filename].List[recipientUsername] = uuid_TO_file
		file_uuid_bytes, err := json.Marshal(file_uuid)
		userlib.DatastoreSet(uuid_TO_file, file_uuid_bytes)

		//Init invitation
		invitation.Uuid_TO_file = uuid_TO_file
		invitation.Owner_name = userdata.Username
		invitation.Sender_name = userdata.Username
		invitation.Key_file = file_manager.Owned_enc_int[filename][0]
		invitation.Key_hmac_file = file_manager.Owned_enc_int[filename][1]
		invitation.Uuid_to_hmac = file_manager.Owned_uuid_to_hmac[filename]
		if !ok {
			return uuid.Nil, errors.New("can't find mac 3")
		}
		invitation.Recipient_name = recipientUsername

		//use hmac_file as the signature
		invitation.RSA_signature, err = userlib.DSSign(userdata.Sk_sign, invitation.Key_file)

		//marshal into bytes
		invitation_bytes, err := json.Marshal(invitation)
		if err != nil {
			return uuid.Nil, err
		}
		//Below is hybrid encryption
		//generate symmetric key
		sym_key := userlib.RandomBytes(16)
		//encrypt sym_key
		enc_sym_key, err := userlib.PKEEnc(enc_key, sym_key)
		if err != nil {
			return uuid.Nil, err
		}

		//encrypt invitation
		invitation_enc := userlib.SymEnc(sym_key, userlib.RandomBytes(16), invitation_bytes)

		//store in datastore
		userlib.DatastoreSet(invitationPtr, invitation_enc)

		//init envelop
		envelop_ptr := uuid.New()
		var envelop Envelop = Envelop{
			invitationPtr,
			enc_sym_key,
		}

		envelop_bytes, err := json.Marshal(envelop)
		if err != nil {
			return uuid.Nil, err
		}

		//store envelop
		userlib.DatastoreSet(envelop_ptr, envelop_bytes)
		invitationPtr = envelop_ptr

		// convert file_manager to bytes
		file_manager_bytes, err := json.Marshal(file_manager)
		if err != nil {
			return uuid.Nil, err
		}
		// Encrypt file_manager
		file_manager_enc := userlib.SymEnc(userdata.Symmetric_key_file_manager, userlib.RandomBytes(16), file_manager_bytes)

		// store back to datastore
		userlib.DatastoreSet(userdata.Uuid_File_manager, file_manager_enc)

		/////////// If Share is not own //////////////
	} else if uuid_TO_file, ok := file_manager.Shared_uuid[filename]; ok {

		//Init invitation
		invitation.Uuid_TO_file = uuid_TO_file
		invitation.Owner_name = file_manager.Shared_owner_name[filename]
		invitation.Sender_name = userdata.Username
		invitation.Key_file = file_manager.Shared_enc_int[filename][0]
		invitation.Key_hmac_file = file_manager.Shared_enc_int[filename][1]
		invitation.Uuid_to_hmac = file_manager.Shared_uuid_to_hmac[filename]
		if !ok {
			return uuid.Nil, errors.New("can't find mac 3")
		}
		invitation.Recipient_name = recipientUsername

		//use hmac_file as the signature
		invitation.RSA_signature, err = userlib.DSSign(userdata.Sk_sign, invitation.Key_file)

		//marshal into bytes
		invitation_bytes, err := json.Marshal(invitation)
		if err != nil {
			return uuid.Nil, err
		}

		//Below is hybrid encryption
		//generate symmetric key
		sym_key := userlib.RandomBytes(16)
		//encrypt sym_key
		enc_sym_key, err := userlib.PKEEnc(enc_key, sym_key)
		if err != nil {
			return uuid.Nil, err
		}

		//encrypt invitation
		invitation_enc := userlib.SymEnc(sym_key, userlib.RandomBytes(16), invitation_bytes)

		//store in datastore
		userlib.DatastoreSet(invitationPtr, invitation_enc)

		//init envelop
		envelop_ptr := uuid.New()
		var envelop Envelop = Envelop{
			invitationPtr,
			enc_sym_key,
		}

		envelop_bytes, err := json.Marshal(envelop)
		if err != nil {
			return uuid.Nil, err
		}

		//store envelop
		userlib.DatastoreSet(envelop_ptr, envelop_bytes)
		invitationPtr = envelop_ptr

	} else {
		return uuid.Nil, errors.New("filename not exist")
	}
	return invitationPtr, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//Get envelop
	envelop_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("can;t find enc envelop")
	}

	//unmarshal
	var envelop *Envelop = &Envelop{}
	err := json.Unmarshal(envelop_bytes, envelop)
	if err != nil {
		return errors.New("can't unmarshal")
	}

	invitationPtr = envelop.Uuid_to_invitation

	//decrypt sym key
	invitation_sym_key, err := userlib.PKEDec(userdata.Sk_decrypt, envelop.Enc_sym_key)
	if err != nil {
		return errors.New("can't decrypt sym key")
	}

	//get enc invitation
	enc_invitation_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("can't find invitation")
	}

	//decrypt invitation
	invitation_bytes := userlib.SymDec(invitation_sym_key, enc_invitation_bytes)

	//unmarshal invitation
	var invitation *Invitation = &Invitation{}
	err = json.Unmarshal(invitation_bytes, invitation)

	//get the sender verify key
	vk, ok := userlib.KeystoreGet(senderUsername + "-verify")
	if !ok {
		return errors.New("can't find sender name")
	}

	//verify
	err = userlib.DSVerify(vk, invitation.Key_file, invitation.RSA_signature)
	if err != nil {
		return errors.New("invitation has been modified")
	}

	//adding file to file manager
	//Get file manager
	file_manager, err := GetFileManager(userdata.Uuid_File_manager, userdata.Symmetric_key_file_manager)
	if err != nil {
		return errors.New("can't get file manager")
	}

	if _, exists := file_manager.Owned_uuid[filename]; exists {
		return errors.New("filename exist 1")
	}

	//Getting information
	file_manager.Shared_uuid[filename] = invitation.Uuid_TO_file
	file_manager.Shared_owner_name[filename] = invitation.Owner_name
	file_manager.Shared_enc_int[filename] = [2][]byte{
		invitation.Key_file,
		invitation.Key_hmac_file,
	}
	file_manager.Shared_uuid_to_hmac[filename] = invitation.Uuid_to_hmac

	//convert file_manager to bytes
	file_manager_bytes, err := json.Marshal(file_manager)
	if err != nil {
		return err
	}
	//Encrypt file_manager
	file_manager_enc := userlib.SymEnc(userdata.Symmetric_key_file_manager, userlib.RandomBytes(16), file_manager_bytes)

	//store back to datastore
	userlib.DatastoreSet(userdata.Uuid_File_manager, file_manager_enc)

	if uuid_TO_file, ok := file_manager.Shared_uuid[filename]; ok {
		uuid_file_bytes, _ := userlib.DatastoreGet(uuid_TO_file)
		var uuid_file *userlib.UUID = &userlib.UUID{}
		err = json.Unmarshal(uuid_file_bytes, uuid_file)
		if err != nil {
			return err
		}
	}

	return nil
}

// Helper function to retrieve and decrypt a File_Manager
func GetFileManager(uuid_file_manager userlib.UUID, symmetric_key_filemanager []byte) (*File_Manager, error) {
	// Retrieve the encrypted file manager
	enc_file_manager, ok := userlib.DatastoreGet(uuid_file_manager)
	if !ok {
		return nil, errors.New("can't find file manager")
	}

	// Decrypt the File_Manager
	file_manager_bytes := userlib.SymDec(symmetric_key_filemanager, enc_file_manager)

	// Create an instance of File_Manager
	var file_manager File_Manager

	// Convert file_manager_bytes to JSON
	err := json.Unmarshal(file_manager_bytes, &file_manager)
	if err != nil {
		return nil, err
	}

	return &file_manager, nil
}

func GetFile(owner bool, uuid userlib.UUID, file_sym_key, file_hmac_key, file_hmac []byte) (file *File, err error) {
	//get encrypted file in datastore
	var file_enc []byte
	var ok bool
	if owner {
		file_enc, ok = userlib.DatastoreGet(uuid)
		if !ok {
			err = errors.New("can't find file struct")
			return nil, err
		}
	} else {
		uuid_file_bytes, ok := userlib.DatastoreGet(uuid)
		var uuid_file *userlib.UUID = &userlib.UUID{}
		err = json.Unmarshal(uuid_file_bytes, uuid_file)

		if !ok {
			err = errors.New("got revoked 1")
			return nil, err
		}
		file_enc, ok = userlib.DatastoreGet(userlib.UUID(*uuid_file))
		if !ok {
			err = errors.New("got revoked 2")
			return nil, err
		}
	}

	//verify
	hmac, err := userlib.HMACEval(file_hmac_key, file_enc)
	if err != nil {
		return nil, err
	}
	if !userlib.HMACEqual(hmac, file_hmac) {
		err = errors.New("File struct has been modified")
		return nil, err
	}

	if len(file_enc) <= 0 {
		return nil, errors.New("got revoked")
	}
	// decrypt file
	file_bytes := userlib.SymDec(file_sym_key, file_enc)

	file = &File{}

	//unmarshal
	err = json.Unmarshal(file_bytes, file)
	if err != nil {
		return nil, err
	}

	return file, err
}

func GetContent(file *File) (content []byte, err error) {
	//get information to verify and decrypted
	content = nil
	for _, each := range file.Blocks {
		block, ok := userlib.DatastoreGet(each.Uuid)
		if !ok {
			err = errors.New("block uuid doesn't exist")
			return nil, err
		}

		//calculate hmac of a block
		block_hmac, err := userlib.HMACEval(file.Hmac_key, block)
		if err != nil {
			return nil, err
		}

		//verify
		if !userlib.HMACEqual(each.Hmac, block_hmac) {
			err = errors.New("block has been modified")
			return nil, err
		}

		//decrypt
		data := userlib.SymDec(file.Sym_key, block)

		content = append(content, data...)
	}
	return content, err
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//get file_manager
	file_manager, err := GetFileManager(userdata.Uuid_File_manager, userdata.Symmetric_key_file_manager)
	if err != nil {
		return err
	}

	//check if filename exist in owner
	if _, exist := file_manager.Owned_uuid[filename]; !exist {
		return errors.New("filename not exist")
	}

	//check if recipient is sharing the file
	if _, exist := file_manager.Owned_sharee[filename].List[recipientUsername]; !exist {
		return errors.New("this recipient is not sharing this file")
	}

	//Getting the hmac of the file
	hmac, ok := userlib.DatastoreGet(file_manager.Owned_uuid_to_hmac[filename])
	if !ok {
		return errors.New("can't find hmac for file")
	}
	//Getting the file
	file, err := GetFile(true, file_manager.Owned_uuid[filename], file_manager.Owned_enc_int[filename][0], file_manager.Owned_enc_int[filename][1], hmac)
	if err != nil {
		return err
	}

	//DELETE BLOCK
	userlib.DatastoreSet(file_manager.Owned_uuid[filename], nil)

	///////MOVE BLOCKS ////////
	for index, block := range file.Blocks {
		//get data block
		enc_block, ok := userlib.DatastoreGet(block.Uuid)
		if !ok {
			return errors.New("can't find enc block")
		}

		//generate a new uuid for the block
		new_uuid := uuid.New()
		//init new block
		var new_block = Block{new_uuid, block.Hmac}
		file.Blocks[index] = new_block

		//move data block to new location
		userlib.DatastoreSet(new_uuid, enc_block)
	}

	///////// MOVE FILE //////////
	//generate uuid for file

	file_uuid := uuid.New()
	//generate keys for file
	file_sym_key := userlib.RandomBytes(16)
	file_hmac_key := userlib.RandomBytes(16)
	uuid_to_hmac := uuid.New()
	file_manager.Owned_uuid[filename] = file_uuid
	temp := file_manager.Owned_enc_int[filename]
	temp[0] = file_sym_key
	temp[1] = file_hmac_key
	file_manager.Owned_enc_int[filename] = temp

	//Process file into bytes
	file_bytes, err := json.Marshal(file)
	if err != nil {
		return err
	}

	//encrypt file
	file_enc := userlib.SymEnc(file_sym_key, userlib.RandomBytes(16), file_bytes)
	//hmac file
	file_hmac, err := userlib.HMACEval(file_hmac_key, file_enc)
	if err != nil {
		return err
	}
	//store hmac to uuid_to_hmac
	userlib.DatastoreSet(uuid_to_hmac, file_hmac)
	//store file to datastore
	userlib.DatastoreSet(file_uuid, file_enc)
	//Update file manager
	file_manager.Owned_uuid_to_hmac[filename] = uuid_to_hmac

	//update sharees with new location. except the revoked one
	marshaled_uuid, err := json.Marshal(file_uuid)
	if err != nil {
		return err
	}

	for name, uuid := range file_manager.Owned_sharee[filename].List {
		if name == recipientUsername {
			continue
		}
		userlib.DatastoreSet(uuid, marshaled_uuid)
	}

	// convert file_manager to bytes
	file_manager_bytes, err := json.Marshal(file_manager)
	if err != nil {
		return err
	}
	// Encrypt file_manager
	file_manager_enc := userlib.SymEnc(userdata.Symmetric_key_file_manager, userlib.RandomBytes(16), file_manager_bytes)

	// store back to datastore
	userlib.DatastoreSet(userdata.Uuid_File_manager, file_manager_enc)

	return nil
}

////////////////READ THIS: USING SENDER NAME
////////AND RECIPIENT NAME AS THE UUID OR SYM_KEY FOR SHARING
