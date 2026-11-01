use iced::widget::{column, container, row, text, button};
use iced::{Element, Task, Theme, Color, Length, Background, Border, border};
use iced::theme::Palette;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Page {
    AllItems,
    Favorites,
    Bin,
    Archived,
}

pub struct NavPanel {
    pub navPage: Page,
}

#[derive(Debug, Clone)]
pub enum Message {
    PageSelected(Page),
}

/*
 * I had to use AI mainly for the button func and stuff.
 */
impl NavPanel {
    pub fn new() -> Self {
        Self {
            navPage: Page::AllItems,
        }
    }

    pub fn update(&mut self, message: Message) {
        match message {
            Message::PageSelected(page) => {
                self.navPage = page;
            }
        }
    }

    fn button<'a>(&self, label: &'a str, page: Page, start: bool, end: bool) -> Element<'a, Message> {
        let isSelected = self.navPage == page;

        let radius = if start {
            border::top(8)
        } else if end {
            border::bottom(8)
        } else {
            border::radius(0)
        };

        button(text(label))
            .on_press(Message::PageSelected(page))
            .width(Length::Fill)
            .padding([7, 10])
            .style(move |_theme, _status| button::Style {
                background: if (isSelected) {
                    Some(Background::Color(Color::from_rgb8(137, 180, 250)))
                } else {
                    None
                },
                text_color: if (isSelected) {
                    Color::from_rgb8(24, 24, 37)
                } else {
                    Color::from_rgb8(205, 214, 244)
                },
                border: Border {
                    radius: radius,
                    ..Default::default()
                },
                ..Default::default()
            })
            .into()
    }

    pub fn view(&self) -> Element<'_, Message> {
        container(
            column![
                self.button("All Items", Page::AllItems, true, false),
                self.button("Favorites", Page::Favorites, false, false),
                self.button("Bin", Page::Bin, false, false),
                self.button("Archived", Page::Archived, false, false),
            ]
            .width(150)
        )
        .height(Length::Fill)
        .style(|_theme| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x18, 0x18, 0x25))),
            border: Border {
                radius: border::radius(8),
                ..Default::default()
            },
            ..Default::default()
        })
        .into()
    }
}