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
    const elementRead = document.createElement("p");
    const elementButton = document.createElement("button");   //creates delete button
    elementButton.textContent = 'Delete'
    elementButton.id = [i]; // reasoning = to know where in myLibrary array to delete
    const title = document.createTextNode(`Book Title: ${array[i].title}`); //refers to book object constructor
    const author = document.createTextNode(`Author: ${array[i].author}`);
    const pages = document.createTextNode(`Pages: ${array[i].pages}`);
    const read = document.createTextNode(`${array[i].wasRead}`);

    elementTitle.appendChild(title);
    elementAuthor.appendChild(author);
    elementPages.appendChild(pages);
    elementRead.appendChild(read);

    div.style.background = '#FFC75F';
    div.setAttribute('class', 'cards');
    div.id = `book${i}`
    document.getElementById("container").appendChild(div);            //adds the elements and their contents
    document.getElementById(`book${i}`).appendChild(elementTitle);    //to the div
    document.getElementById(`book${i}`).appendChild(elementAuthor);
    document.getElementById(`book${i}`).appendChild(elementPages);
    document.getElementById(`book${i}`).appendChild(elementRead);
    document.getElementById(`book${i}`).appendChild(elementButton);
  }
  document.querySelectorAll('#container .cards >button').forEach(div => div.onclick = (e) => {
    const removeFromArray = e.target.id // this selects the button which is created with a unique ID of n of the array
    storeDelArray(removeFromArray);
    
    const deleting = e.target.parentElement; 
    deleting.remove();
  })
}

const addForm = document.forms["book-form"];
addForm.reset();
addForm.addEventListener("submit", function(e){  // takes form input

  e.preventDefault();
  let bookTitle = document.getElementById("book-title").value; 
  let authorName = document.getElementById("author").value;
  let pageCount = document.getElementById("pages").value;
  let boolValueTrue = document.getElementById("finished").value;
  let boolValueFalse = document.getElementById("notfinished").value;
  let valueResults = true;
  console.log(boolValueFalse);
  console.log(boolValueTrue);
  
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
});

const showForm = document.getElementById("show-form");
const formContainer = document.getElementById("forms-container")

showForm.addEventListener('click', function handleClick(){      //shows or hides form in dom

  if (formContainer.style.display === 'none') {
    formContainer.style.display = 'block';
    // document.body.style.background = 'black';  
  }

  else{
    formContainer.style.display = 'none';
    
  }

});