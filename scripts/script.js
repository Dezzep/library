const showForm = document.getElementById("show-form");
const formContainer = document.getElementById("forms-container")
let myLibrary = [];
let storeDeletedArray = []; //stores indexes of delete button press for later use
function Book(title, author, pages, wasRead){   //constructor for book
  this.title = title;
  this.author = author;
  this.pages = pages;
  this.wasRead = wasRead;
  if (this.wasRead === false){
      this.wasRead = 'Not read yet';
  
      }
    else{
      this.wasRead = 'Finished Reading'
    }}
           
function storeDelArray(deletedItems){ //stores the array of deleted items
  storeDeletedArray.push(deletedItems); //later sorts them from last index to first and deleted
  
}

function addBookToLibrary(array) {    //every time a form is submitted, this should be called.
  
  for (i in array){
   
    const div = document.createElement("div");            
    const elementTitle = document.createElement("p");     //creates paragraphs to store content
    const elementAuthor = document.createElement("p");
    const elementPages = document.createElement("p");
    const elementRead = document.createElement("button");
    const elementButton = document.createElement("button");   //creates delete button
    elementButton.textContent = 'Delete'
    elementButton.id = [i]; // reasoning = to know where in myLibrary array to delete
    elementRead.id = [i]
    const title = document.createTextNode(`Book Title: ${array[i].title}`); //refers to book object constructor
    const author = document.createTextNode(`Author: ${array[i].author}`);
    const pages = document.createTextNode(`Pages: ${array[i].pages}`);
    const read = document.createTextNode(`${array[i].wasRead}`);

    elementTitle.appendChild(title);
    elementAuthor.appendChild(author);
    elementPages.appendChild(pages);
    elementRead.appendChild(read);
    
    if (array[i].wasRead === "Finished Reading" ){
    elementRead.style.background = "#008B74"}
     else{
       elementRead.style.background = "red";
     }

    div.style.background = '#FFC75F';
    div.setAttribute('class', 'cards');
    div.id = `book${i}`;
    document.getElementById("container").appendChild(div);            //adds the elements and their contents
    document.getElementById(`book${i}`).appendChild(elementTitle);    //to the div
    document.getElementById(`book${i}`).appendChild(elementAuthor);
    document.getElementById(`book${i}`).appendChild(elementPages);
    document.getElementById(`book${i}`).appendChild(elementRead);
    elementRead.setAttribute('class', 'read-status');
    document.getElementById(`book${i}`).appendChild(elementButton);
    elementButton.setAttribute('class', 'delete-button');
  }
  document.querySelectorAll('#container .cards >.delete-button').forEach(div => div.onclick = (e) => {
    const removeFromArray = e.target.id // this selects the button which is created with a unique ID of n of the array
    storeDelArray(removeFromArray);
    
    const deleting = e.target.parentElement; 
    deleting.remove();
  });

  document.querySelectorAll('#container .cards >.read-status').forEach(div => div.onclick = (e) => {
    let index = e.target.id; // this selects the button which is created with a unique ID of n of the array
    
    if(array[index].wasRead === 'Finished Reading'){
      array[index].wasRead = 'Not read yet';
      e.target.style.background = "red";
      e.target.innerText= "Not read yet"
    }
    else{
      array[index].wasRead = 'Finished Reading';
      e.target.style.background = "#008B74";
      e.target.innerText = "Finished Reading"
    }
   });
}

const addForm = document.forms["book-form"];
addForm.reset();
addForm.addEventListener("submit", function(e){  // takes form input

  e.preventDefault();
  let bookTitle = document.getElementById("book-title").value; 
  let authorName = document.getElementById("author").value;
  let pageCount = document.getElementById("pages").value;
  let valueResults = true;
 
  if (document.getElementById('notfinished').checked){
    valueResults = false;
  }
  
  const removeChilds = (parent) => {
    while (parent.lastChild) {
      parent.removeChild(parent.lastChild);
  }};
  
  removeChilds(document.getElementById("container"));

  storeDeletedArray.sort().reverse();
   for (i in storeDeletedArray){

    myLibrary.splice(storeDeletedArray[i], 1);
   }
  storeDeletedArray = [];         
  
  addForm.style.display="none";
  addForm.style.display="block";                              
  
  myLibrary.push(book = new Book(bookTitle, authorName, pageCount, valueResults));
  addBookToLibrary(myLibrary);
  
  addForm.reset();
  formContainer.style.display = 'none';
});

showForm.addEventListener('click', function handleClick(){      //shows or hides form in dom

  if (formContainer.style.display === 'none') {
    formContainer.style.display = 'block';
    const bookTitleSelect = document.getElementById("book-title");
    bookTitleSelect.focus();
 
  }
  else{
    formContainer.style.display = 'none';
  }
});




