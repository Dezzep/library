



function Book(title, author, pages, wasRead){
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

function addBookToLibrary(array) {
  for (i in array){
    console.log(array[i])
    console.log(array[i].title)

    let div = document.createElement("div");
    let h1 = document.createElement("h1")
    let p = document.createTextNode("p");
    let x = document.createTextNode('X');
  div.style.background = 'red';
  div.setAttribute('class', 'cards');
 
  div.id = `book${i}`
  
  div.innerText = `Book Name: ${array[i].title} \n
  Author: ${array[i].author} \n
  Pages: ${array[i].pages} \n
  ${array[i].wasRead}`

  p.innerText = 'blah';
    document.getElementById("container").appendChild(div);



    
    

    
  }
}

const book1 = new Book('hobbit', 'J.R.R. Tolkien', '295 pages', true);
const book2 = new Book('Taco', 'block', '25', false,)


let myLibrary = [book1, book2]
addBookToLibrary(myLibrary)

